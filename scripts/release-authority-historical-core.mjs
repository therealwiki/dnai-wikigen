import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  normalizePhalaPostMeasurementActivationExecutionReceipt,
  phalaPostMeasurementActivationExecutionReceiptSha256,
  phalaPostMeasurementRuntimeCommitmentsSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import {
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";

export const CEREMONY_AUTHORIZATION_CORE_SCHEMA =
  "dnai.ceremony-authorization-core.v1";
export const CEREMONY_AUTHORIZATION_CORE_STATUS =
  "pre_ceremony_authorized";
export const CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_KIND =
  "ceremony_authorization";
export const CEREMONY_AUTHORIZATION_CORE_DOMAIN =
  "dnai-wikigen/ceremony-authorization-core/v1\0";
export const CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_DOMAIN =
  "dnai-wikigen/ceremony-authorization-review-subject/v1\0";

export const LIVE_ACTIVATION_AUTHORITY_SCHEMA =
  "dnai.live-activation-authority.v5";
export const LIVE_ACTIVATION_AUTHORITY_STATUS =
  "live_activation_authorized";
export const LIVE_ACTIVATION_REVIEW_SUBJECT_KIND =
  "live_activation_authority";
export const LIVE_ACTIVATION_AUTHORITY_DOMAIN =
  "dnai-wikigen/live-activation-authority/v5\0";
export const LIVE_ACTIVATION_REVIEW_SUBJECT_DOMAIN =
  "dnai-wikigen/live-activation-review-subject/v5\0";

export const RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA =
  "dnai.release-authority-cryptographic-review.v2";
export const RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA =
  "dnai.release-authority-review-signing-payload.v2";
export const RELEASE_AUTHORITY_REVIEW_SIGNING_DOMAIN =
  "dnai-wikigen/release-authority-cryptographic-review-signing/v2\0";
export const RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX =
  "dnai-wikigen release-authority cryptographic review v2:";
export const RELEASE_AUTHORITY_SIGNATURE_SCHEME =
  "eip191_personal_sign_secp256k1_low_s_65_byte";

export const RELEASE_CEREMONY_TRANSACTION_PLAN_SCHEMA =
  "dnai.release-ceremony-transaction-plan.v1";
export const RELEASE_CEREMONY_LOCK_PROTOCOL =
  "dnai.release-ceremony-lock.v1";

export const CEREMONY_TRANSACTION_RPC_OBSERVATION_SCHEMA =
  "dnai.base-sepolia-transaction-rpc-observation.v1";
export const CEREMONY_TRANSACTION_RPC_OBSERVATION_DOMAIN =
  "dnai-wikigen/base-sepolia-transaction-rpc-observation/v1\0";
export const CEREMONY_RECEIPT_RPC_OBSERVATION_SCHEMA =
  "dnai.base-sepolia-receipt-rpc-observation.v1";
export const CEREMONY_RECEIPT_RPC_OBSERVATION_DOMAIN =
  "dnai-wikigen/base-sepolia-receipt-rpc-observation/v1\0";
export const COMMON_FINALIZED_BLOCK_RPC_OBSERVATION_SCHEMA =
  "dnai.base-sepolia-finalized-block-rpc-observation.v1";
export const COMMON_FINALIZED_BLOCK_RPC_OBSERVATION_DOMAIN =
  "dnai-wikigen/base-sepolia-finalized-block-rpc-observation/v1\0";
export const EXECUTION_POLICY_ANCHOR_RPC_READ_SCHEMA =
  "dnai.execution-policy-anchor-rpc-read.v1";
export const EXECUTION_POLICY_ANCHOR_RPC_READ_DOMAIN =
  "dnai-wikigen/execution-policy-anchor-rpc-read/v1\0";
export const LIVE_ACTIVATION_FRONTEND_BINDING_SCHEMA =
  "dnai.live-activation-frontend-binding.v3";
export const LIVE_ACTIVATION_FRONTEND_BINDING_DOMAIN =
  "dnai-wikigen/live-activation-frontend-binding/v3\0";
export const LIVE_ACTIVATION_FRONTEND_BINDING_TRUTH_STATUS =
  "derived_from_signed_live_activation_not_standalone_authority";

export const HISTORICAL_LIVE_ACTIVATION_EXPECTED_CONTEXT_SCHEMA =
  "dnai.historical-live-activation-expected-context.v1";
export const HISTORICAL_LIVE_ACTIVATION_EXPECTED_CONTEXT_TRUTH =
  "independently_normalized_l_r_plan_and_release_authority_projection_for_signed_c";

export const MAX_RELEASE_AUTHORITY_REVIEW_LIFETIME_MS = 60 * 60 * 1_000;
export const MIN_RELEASE_AUTHORITY_REVIEW_HEADROOM_MS = 5 * 60 * 1_000;

export const RELEASE_CEREMONY_MUTATION_WRITERS = Object.freeze([
  "challenge_registry_release",
  "compute_release",
  "diligence_release",
  "email_oracle_release",
  "execution_policy_anchor_release",
  "tinker_release",
]);

export const RELEASE_CONTRACT_STATE_KEYS = Object.freeze([
  "diligence_room",
  "tinker_account_encumbrance",
  "royalty_distributor",
  "challenge_registry",
  "compute_credit_vault",
  "email_oracle_auth",
  "execution_policy_anchor",
]);

export const RELEASE_CVM_KEYS = Object.freeze([
  "main_runtime_cvm",
  "diligence_qvl_cvm",
  "arena_qvl_cvm",
  "anchor_writer_qvl_cvm",
  "compute_workload_qvl_cvm",
  "compute_metering_qvl_cvm",
  "independent_metering_cvm",
]);

const CONTROL_ROLE_BY_CONTRACT = Object.freeze({
  diligence_room: "developer",
  tinker_account_encumbrance: "owner",
  royalty_distributor: "immutable_no_owner",
  challenge_registry: "owner",
  compute_credit_vault: "owner",
  email_oracle_auth: "owner",
  execution_policy_anchor: "owner",
});

const STAGE_ONE_DEPENDENCY_KINDS = Object.freeze([
  "deployment_intent",
  "reviewer_authority_genesis",
  "reviewer_authority_genesis_acceptance",
  "fresh_contract_deployment_receipt",
  "immutable_deployment_manifest",
  "ceremony_ledger_initialization_receipt",
  "ceremony_ledger_initial",
  "ceremony_transaction_plan",
  "cvm_launch_intent",
  "cvm_nonlive_bootstrap_authorization_receipt",
  "pre_ceremony_runtime_authority",
]);

const STAGE_TWO_DEPENDENCY_KINDS = Object.freeze([
  "ceremony_authorization",
  "immutable_deployment_manifest",
  "ceremony_ledger_initialization_receipt",
  "frozen_final_ceremony_ledger",
  "ceremony_ledger_finalization_receipt",
  "ceremony_ledger_revision_chain",
  "common_finalized_state",
  "contract_configuration_set",
  "challenge_genesis",
  "final_cvm_state",
  "cvm_measurements",
  "tdx_attestation_bundle",
  "qvl_policy_bundle",
  "post_measurement_activation_execution_receipt",
  "compute_workload_activation_observation",
  "compute_workload_browser_binding",
  "frontend_release_env",
  "frontend_build_candidate_receipt",
  "frontend_build",
]);

const CHAIN_ID = 84_532;
const NETWORK_NAME = "base-sepolia";
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_TRANSACTIONS = 512;
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const ADDRESS_OR_ZERO = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32_OR_ZERO = /^0x[0-9a-f]{64}$/;
const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/;
const LOGS_BLOOM = /^0x[0-9a-f]{512}$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const UTC_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UTC_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const SECP256K1_N = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
);
const SECP256K1_HALF_N = SECP256K1_N / 2n;
const REVIEWER_HASH_DOMAIN = "dnai-wikigen/execution-policy-approver/v1\0";
const REVIEWER_ROOT_DOMAIN = "dnai-wikigen/execution-policy-approver-root/v1\0";
const REVIEWER_SET_DOMAIN = "dnai-wikigen/release-reviewer-set/v1\0";
const BROWSER_BINDING_DOMAIN =
  "dnai-wikigen/compute-workload-browser-binding/v2\0";

export class HistoricalReleaseAuthorityValidationError extends TypeError {}

function fail(message) {
  throw new HistoricalReleaseAuthorityValidationError(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields do not match the exact schema`);
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

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function utf8ByteLength(value) {
  return new TextEncoder().encode(value).byteLength;
}

function assertBoundedCanonicalGraph(value, label) {
  try {
    assertCanonicalPlainDataGraph(value, {
      label,
      maximumDepth: 48,
      maximumNodes: 20_000,
    });
  } catch (error) {
    fail(error.message);
  }
  const text = JSON.stringify(value);
  if (utf8ByteLength(text) > MAX_BYTES) fail(`${label} exceeds the byte bound`);
}

function exactString(value, expected, label) {
  if (value !== expected) fail(`${label} must equal ${expected}`);
  return value;
}

function fixed(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${label} is not canonical`);
  }
  return value;
}

function sha256(value, label) {
  return fixed(value, SHA256, label);
}

function bareSha256(value, label) {
  return fixed(value, BARE_SHA256, label);
}

function bytes32(value, label, { allowZero = false } = {}) {
  return fixed(value, allowZero ? BYTES32_OR_ZERO : BYTES32, label);
}

function address(value, label, { allowZero = false } = {}) {
  const normalized = fixed(value, allowZero ? ADDRESS_OR_ZERO : ADDRESS, label);
  if (!allowZero && normalized === ZERO_ADDRESS) fail(`${label} must be nonzero`);
  return normalized;
}

function boundedIdentifier(value, label) {
  return fixed(value, IDENTIFIER, label);
}

function appId(value, label) {
  return fixed(value, APP_ID, label);
}

function integer(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be a bounded safe integer`);
  }
  return value;
}

function decimal(value, label) {
  fixed(value, DECIMAL, label);
  try {
    if (BigInt(value) >= (1n << 256n)) fail(`${label} exceeds uint256`);
  } catch {
    fail(`${label} must be a canonical uint256 decimal string`);
  }
  return value;
}

function millisecondTimestamp(value, label) {
  const milliseconds = typeof value === "string" ? Date.parse(value) : NaN;
  if (!UTC_MILLISECONDS.test(String(value)) || !Number.isFinite(milliseconds)
    || new Date(milliseconds).toISOString() !== value) {
    fail(`${label} must be canonical millisecond UTC`);
  }
  return milliseconds;
}

function secondTimestamp(value, label) {
  const milliseconds = typeof value === "string" ? Date.parse(value) : NaN;
  if (!UTC_SECOND.test(String(value)) || !Number.isFinite(milliseconds)
    || new Date(milliseconds).toISOString().replace(".000Z", "Z") !== value) {
    fail(`${label} must be canonical UTC second`);
  }
  return milliseconds;
}

function canonicalAbsolutePath(value, label) {
  if (typeof value !== "string" || !value.startsWith("/")
    || value.includes("\\") || value.includes("\0") || value.includes("//")) {
    fail(`${label} must be a canonical absolute POSIX path`);
  }
  const segments = value.split("/").slice(1);
  if (segments.length < 1 || segments.some((entry) => (
    entry.length < 1 || entry === "." || entry === ".."
  ))) {
    fail(`${label} must be a canonical absolute POSIX path`);
  }
  return value;
}

function network(value, label) {
  const parsed = exactRecord(value, ["chain_id", "name"], label);
  return {
    chain_id: integer(parsed.chain_id, `${label}.chain_id`, CHAIN_ID, CHAIN_ID),
    name: exactString(parsed.name, NETWORK_NAME, `${label}.name`),
  };
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) fail(`${label} drifted from the injected authority`);
}

function normalizeExpectedToolchain(value) {
  assertBoundedCanonicalGraph(value, "expected deployment toolchain");
  if (!isRecord(value)) fail("expected deployment toolchain must be an object");
  return structuredClone(value);
}

function normalizePlanTransaction(value, index) {
  const parsed = exactRecord(value, [
    "calldata_sha256", "nonce", "sequence", "signer_address", "to",
    "value_wei", "writer_id",
  ], `ceremony transaction plan entry ${index}`);
  if (parsed.sequence !== index
    || parsed.writer_id !== RELEASE_CEREMONY_MUTATION_WRITERS[index]) {
    fail("ceremony transaction plan writers must appear once in canonical order");
  }
  return {
    sequence: index,
    writer_id: parsed.writer_id,
    signer_address: address(parsed.signer_address, `plan[${index}].signer_address`),
    nonce: decimal(parsed.nonce, `plan[${index}].nonce`),
    to: address(parsed.to, `plan[${index}].to`),
    value_wei: decimal(parsed.value_wei, `plan[${index}].value_wei`),
    calldata_sha256: sha256(parsed.calldata_sha256, `plan[${index}].calldata_sha256`),
  };
}

export function releaseCeremonyTransactionPlanSha256({
  releaseSha,
  chainId,
  transactions,
}) {
  fixed(releaseSha, SHA40, "transaction-plan release SHA");
  integer(chainId, "transaction-plan chain ID", CHAIN_ID, CHAIN_ID);
  if (!Array.isArray(transactions)
    || transactions.length !== RELEASE_CEREMONY_MUTATION_WRITERS.length) {
    fail("ceremony transaction plan must contain the exact six mutations");
  }
  const normalized = transactions.map(normalizePlanTransaction);
  return domainDigest("dnai-wikigen/release-ceremony-transaction-plan/v1\0", {
    schema: RELEASE_CEREMONY_TRANSACTION_PLAN_SCHEMA,
    release_sha: releaseSha,
    chain_id: chainId,
    transactions: normalized,
  });
}

function normalizeTransactionPlan(value, releaseSha) {
  const parsed = exactRecord(
    value,
    ["plan_sha256", "schema", "transactions"],
    "ceremony transaction plan",
  );
  exactString(
    parsed.schema,
    RELEASE_CEREMONY_TRANSACTION_PLAN_SCHEMA,
    "transaction plan schema",
  );
  if (!Array.isArray(parsed.transactions)
    || parsed.transactions.length !== RELEASE_CEREMONY_MUTATION_WRITERS.length) {
    fail("ceremony transaction plan must contain exactly the six canonical mutations");
  }
  const transactions = parsed.transactions.map(normalizePlanTransaction);
  const lastNonce = new Map();
  for (const entry of transactions) {
    const nonce = BigInt(entry.nonce);
    const prior = lastNonce.get(entry.signer_address);
    if (prior !== undefined && nonce !== prior + 1n) {
      fail("ceremony transaction plan nonces must be contiguous per signer");
    }
    lastNonce.set(entry.signer_address, nonce);
  }
  const planSha256 = releaseCeremonyTransactionPlanSha256({
    releaseSha,
    chainId: CHAIN_ID,
    transactions,
  });
  requireEqual(parsed.plan_sha256, planSha256, "ceremony transaction plan digest");
  return { schema: parsed.schema, plan_sha256: planSha256, transactions };
}

function executionPolicyReviewerHash(reviewerAddress) {
  return createHash("sha256")
    .update(REVIEWER_HASH_DOMAIN, "utf8")
    .update(address(reviewerAddress, "reviewer address"), "ascii")
    .digest("hex");
}

function executionPolicyReviewerRootHash(reviewerHashes) {
  if (!Array.isArray(reviewerHashes) || reviewerHashes.length < 2
    || reviewerHashes.some((entry) => !BARE_SHA256.test(entry))) {
    fail("reviewer hashes must contain at least two bare SHA-256 values");
  }
  const normalized = [...reviewerHashes].sort();
  if (new Set(normalized).size !== normalized.length) {
    fail("reviewer hashes must be unique");
  }
  return createHash("sha256")
    .update(REVIEWER_ROOT_DOMAIN, "utf8")
    .update(JSON.stringify(normalized), "ascii")
    .digest("hex");
}

function reviewerSetSha256(reviewers) {
  return domainDigest(REVIEWER_SET_DOMAIN, reviewers);
}

export function normalizeHistoricalReviewerAuthority(value) {
  assertBoundedCanonicalGraph(value, "historical reviewer authority");
  const parsed = exactRecord(value, [
    "approved_reviewer_hashes", "approved_reviewers",
    "reviewer_authority_current_status_epoch",
    "reviewer_authority_current_status_expires_at",
    "reviewer_authority_current_status_not_before",
    "reviewer_authority_current_status_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_genesis_sha256", "reviewer_root_hash",
    "reviewer_set_sha256",
  ], "historical reviewer authority");
  if (!Array.isArray(parsed.approved_reviewers)
    || parsed.approved_reviewers.length < 2 || parsed.approved_reviewers.length > 32) {
    fail("historical reviewer authority must contain two through 32 reviewers");
  }
  const approvedReviewers = parsed.approved_reviewers.map((value, index) => {
    const reviewer = exactRecord(
      value,
      ["address", "controller_id"],
      `historical reviewer ${index}`,
    );
    if (!CONTROLLER.test(reviewer.controller_id)) {
      fail(`historical reviewer ${index} controller is invalid`);
    }
    return {
      address: address(reviewer.address, `historical reviewer ${index} address`),
      controller_id: reviewer.controller_id,
    };
  });
  for (let index = 1; index < approvedReviewers.length; index += 1) {
    if (approvedReviewers[index - 1].address >= approvedReviewers[index].address) {
      fail("historical reviewers must be strictly sorted by address");
    }
  }
  if (new Set(approvedReviewers.map((entry) => entry.controller_id)).size
      !== approvedReviewers.length) {
    fail("historical reviewer controllers must be distinct");
  }
  const hashes = approvedReviewers
    .map((entry) => executionPolicyReviewerHash(entry.address))
    .sort();
  if (!same(parsed.approved_reviewer_hashes, hashes)
    || parsed.reviewer_root_hash !== executionPolicyReviewerRootHash(hashes)
    || parsed.reviewer_set_sha256 !== reviewerSetSha256(approvedReviewers)) {
    fail("historical reviewer identities do not match their exact root and set pins");
  }
  const currentStatusNotBefore = secondTimestamp(
    parsed.reviewer_authority_current_status_not_before,
    "reviewer authority current-status not_before",
  );
  const currentStatusExpiresAt = secondTimestamp(
    parsed.reviewer_authority_current_status_expires_at,
    "reviewer authority current-status expires_at",
  );
  if (currentStatusExpiresAt <= currentStatusNotBefore) {
    fail("historical reviewer authority current-status window must be positive");
  }
  return deepFreezeCanonicalPlainDataGraph({
    reviewer_authority_genesis_sha256: sha256(
      parsed.reviewer_authority_genesis_sha256,
      "reviewer authority genesis digest",
    ),
    reviewer_authority_genesis_acceptance_sha256: sha256(
      parsed.reviewer_authority_genesis_acceptance_sha256,
      "reviewer authority genesis acceptance digest",
    ),
    reviewer_authority_current_status_epoch: integer(
      parsed.reviewer_authority_current_status_epoch,
      "reviewer authority current-status epoch",
      1,
      0xffff_ffff,
    ),
    reviewer_authority_current_status_not_before:
      parsed.reviewer_authority_current_status_not_before,
    reviewer_authority_current_status_expires_at:
      parsed.reviewer_authority_current_status_expires_at,
    reviewer_authority_current_status_sha256: sha256(
      parsed.reviewer_authority_current_status_sha256,
      "reviewer authority current-status digest",
    ),
    approved_reviewers: approvedReviewers,
    approved_reviewer_hashes: hashes,
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: parsed.reviewer_set_sha256,
  }, { label: "normalized historical reviewer authority" });
}

function normalizeSignatureVerifier(value, expected) {
  assertBoundedCanonicalGraph(value, "review signature verifier");
  if (!isRecord(value) || !same(value, expected)) {
    fail("review signature verifier differs from the injected verifier authority");
  }
  return structuredClone(value);
}

function normalizeLowSSignature(value, label) {
  fixed(value, SIGNATURE, label);
  const r = BigInt(`0x${value.slice(2, 66)}`);
  const s = BigInt(`0x${value.slice(66, 130)}`);
  const v = Number.parseInt(value.slice(130), 16);
  if (r <= 0n || r >= SECP256K1_N || s <= 0n || s > SECP256K1_HALF_N
    || (v !== 27 && v !== 28)) {
    fail(`${label} must use canonical low-s secp256k1 with v 27 or 28`);
  }
  return value;
}

function normalizeDependencyList(value, dependencies) {
  if (!Array.isArray(value) || value.length !== dependencies.length) {
    fail("cryptographic review dependencies are incomplete");
  }
  return value.map((entry, index) => {
    const parsed = exactRecord(
      entry,
      ["kind", "sha256"],
      `review dependency ${index}`,
    );
    requireEqual(parsed.kind, dependencies[index].kind, `review dependency ${index} kind`);
    const pin = sha256(parsed.sha256, `review dependency ${index} digest`);
    requireEqual(pin, dependencies[index].sha256, `review dependency ${parsed.kind}`);
    return { kind: parsed.kind, sha256: pin };
  });
}

export function normalizeHistoricalReviewSigningPayload(value, {
  expectedSignatureVerifier,
} = {}) {
  assertBoundedCanonicalGraph(value, "historical review signing payload");
  const parsed = exactRecord(value, [
    "approved_reviewer_hashes", "chain_id", "dependencies", "expires_at",
    "release_sha", "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_current_status_epoch",
    "reviewer_authority_current_status_sha256",
    "reviewer_authority_genesis_sha256", "reviewer_root_hash",
    "reviewer_set_sha256", "schema", "signature_scheme",
    "signature_verifier", "signed_at", "stage", "subject_kind",
    "subject_sha256",
  ], "historical review signing payload");
  exactString(
    parsed.schema,
    RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA,
    "review signing payload schema",
  );
  if (![
    CEREMONY_AUTHORIZATION_CORE_STATUS,
    LIVE_ACTIVATION_AUTHORITY_STATUS,
  ].includes(parsed.stage)
    || ![
      CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_KIND,
      LIVE_ACTIVATION_REVIEW_SUBJECT_KIND,
    ].includes(parsed.subject_kind)) {
    fail("review signing payload stage or subject kind is invalid");
  }
  exactString(
    parsed.signature_scheme,
    RELEASE_AUTHORITY_SIGNATURE_SCHEME,
    "review signature scheme",
  );
  if (!Array.isArray(parsed.approved_reviewer_hashes)
    || parsed.approved_reviewer_hashes.length < 2
    || parsed.approved_reviewer_hashes.some((entry) => !BARE_SHA256.test(entry))) {
    fail("review approved reviewer hashes are invalid");
  }
  const hashes = [...parsed.approved_reviewer_hashes].sort();
  if (!same(hashes, parsed.approved_reviewer_hashes)
    || new Set(hashes).size !== hashes.length
    || executionPolicyReviewerRootHash(hashes) !== parsed.reviewer_root_hash) {
    fail("review approved reviewer hashes do not match their canonical root");
  }
  millisecondTimestamp(parsed.signed_at, "review signed_at");
  millisecondTimestamp(parsed.expires_at, "review expires_at");
  return {
    schema: parsed.schema,
    stage: parsed.stage,
    subject_kind: parsed.subject_kind,
    release_sha: fixed(parsed.release_sha, SHA40, "review release SHA"),
    chain_id: integer(parsed.chain_id, "review chain ID", CHAIN_ID, CHAIN_ID),
    subject_sha256: sha256(parsed.subject_sha256, "review subject digest"),
    dependencies: parsed.dependencies.map((entry, index) => {
      const dependency = exactRecord(
        entry,
        ["kind", "sha256"],
        `review signing payload dependency ${index}`,
      );
      if (typeof dependency.kind !== "string" || dependency.kind.length < 1) {
        fail(`review signing payload dependency ${index} kind is invalid`);
      }
      return {
        kind: dependency.kind,
        sha256: sha256(dependency.sha256, `review signing payload dependency ${index}`),
      };
    }),
    reviewer_authority_genesis_sha256: sha256(
      parsed.reviewer_authority_genesis_sha256,
      "reviewer authority genesis digest",
    ),
    reviewer_authority_genesis_acceptance_sha256: sha256(
      parsed.reviewer_authority_genesis_acceptance_sha256,
      "reviewer authority genesis acceptance digest",
    ),
    reviewer_authority_current_status_epoch: integer(
      parsed.reviewer_authority_current_status_epoch,
      "reviewer authority current-status epoch",
      1,
      0xffff_ffff,
    ),
    reviewer_authority_current_status_sha256: sha256(
      parsed.reviewer_authority_current_status_sha256,
      "reviewer authority current-status digest",
    ),
    approved_reviewer_hashes: hashes,
    reviewer_root_hash: bareSha256(parsed.reviewer_root_hash, "reviewer root"),
    reviewer_set_sha256: sha256(parsed.reviewer_set_sha256, "reviewer set digest"),
    signed_at: parsed.signed_at,
    expires_at: parsed.expires_at,
    signature_scheme: parsed.signature_scheme,
    signature_verifier: normalizeSignatureVerifier(
      parsed.signature_verifier,
      expectedSignatureVerifier,
    ),
  };
}

export function historicalReleaseAuthorityReviewSigningPayloadSha256(
  value,
  options,
) {
  return domainDigest(
    RELEASE_AUTHORITY_REVIEW_SIGNING_DOMAIN,
    normalizeHistoricalReviewSigningPayload(value, options),
  );
}

export function historicalReleaseAuthorityReviewSigningMessage(value, options) {
  return `${RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX}${
    historicalReleaseAuthorityReviewSigningPayloadSha256(value, options)
  }`;
}

function normalizeCryptographicReview(value, {
  stage,
  subjectKind,
  subjectSha256,
  releaseSha,
  dependencies,
  reviewerAuthority,
  expectedSignatureVerifier,
  verifyReviewSignatures,
}) {
  const parsed = exactRecord(value, [
    "approved_reviewer_hashes", "chain_id", "dependencies", "expires_at",
    "release_sha", "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_current_status_epoch",
    "reviewer_authority_current_status_sha256",
    "reviewer_authority_genesis_sha256", "reviewer_root_hash",
    "reviewer_set_sha256", "schema", "signature_scheme",
    "signature_verifier", "signatures", "signed_at",
    "signing_payload_sha256", "stage", "subject_kind", "subject_sha256",
  ], "historical cryptographic authority review");
  exactString(
    parsed.schema,
    RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
    "review schema",
  );
  exactString(parsed.stage, stage, "review stage");
  exactString(parsed.subject_kind, subjectKind, "review subject kind");
  if (parsed.release_sha !== releaseSha || parsed.chain_id !== CHAIN_ID
    || parsed.subject_sha256 !== subjectSha256) {
    fail("cryptographic review release, chain, stage, or subject binding is invalid");
  }
  if (parsed.reviewer_authority_genesis_sha256
      !== reviewerAuthority.reviewer_authority_genesis_sha256
    || parsed.reviewer_authority_genesis_acceptance_sha256
      !== reviewerAuthority.reviewer_authority_genesis_acceptance_sha256
    || parsed.reviewer_authority_current_status_epoch
      !== reviewerAuthority.reviewer_authority_current_status_epoch
    || parsed.reviewer_authority_current_status_sha256
      !== reviewerAuthority.reviewer_authority_current_status_sha256
    || parsed.reviewer_root_hash !== reviewerAuthority.reviewer_root_hash
    || parsed.reviewer_set_sha256 !== reviewerAuthority.reviewer_set_sha256
    || !same(
      parsed.approved_reviewer_hashes,
      reviewerAuthority.approved_reviewer_hashes,
    )) {
    fail("cryptographic review does not match the injected reviewer authority");
  }
  const normalizedDependencies = normalizeDependencyList(
    parsed.dependencies,
    dependencies,
  );
  const signingPayload = normalizeHistoricalReviewSigningPayload({
    schema: RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA,
    stage: parsed.stage,
    subject_kind: parsed.subject_kind,
    release_sha: parsed.release_sha,
    chain_id: parsed.chain_id,
    subject_sha256: parsed.subject_sha256,
    dependencies: normalizedDependencies,
    reviewer_authority_genesis_sha256:
      parsed.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      parsed.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      parsed.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      parsed.reviewer_authority_current_status_sha256,
    approved_reviewer_hashes: parsed.approved_reviewer_hashes,
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: parsed.reviewer_set_sha256,
    signed_at: parsed.signed_at,
    expires_at: parsed.expires_at,
    signature_scheme: parsed.signature_scheme,
    signature_verifier: parsed.signature_verifier,
  }, { expectedSignatureVerifier });
  const signingPayloadSha256 =
    historicalReleaseAuthorityReviewSigningPayloadSha256(
      signingPayload,
      { expectedSignatureVerifier },
    );
  requireEqual(
    parsed.signing_payload_sha256,
    signingPayloadSha256,
    "review signing payload digest",
  );
  const signedAtMs = millisecondTimestamp(parsed.signed_at, "review signed_at");
  const expiresAtMs = millisecondTimestamp(parsed.expires_at, "review expires_at");
  const reviewerStatusNotBeforeMs = secondTimestamp(
    reviewerAuthority.reviewer_authority_current_status_not_before,
    "reviewer authority current-status not_before",
  );
  const reviewerStatusExpiresAtMs = secondTimestamp(
    reviewerAuthority.reviewer_authority_current_status_expires_at,
    "reviewer authority current-status expires_at",
  );
  if (signedAtMs < reviewerStatusNotBeforeMs
    || signedAtMs >= reviewerStatusExpiresAtMs
    || expiresAtMs > reviewerStatusExpiresAtMs) {
    fail("historical cryptographic review is outside its selected reviewer-status validity window");
  }
  if (expiresAtMs <= signedAtMs
    || expiresAtMs - signedAtMs > MAX_RELEASE_AUTHORITY_REVIEW_LIFETIME_MS) {
    fail("historical cryptographic review is outside its bounded signed lifetime");
  }
  if (!Array.isArray(parsed.signatures) || parsed.signatures.length !== 2) {
    fail("historical cryptographic review requires exactly two signatures");
  }
  const approvedByAddress = new Map(
    reviewerAuthority.approved_reviewers.map((entry) => [
      entry.address,
      entry.controller_id,
    ]),
  );
  const signatures = parsed.signatures.map((entry, index) => {
    const signature = exactRecord(
      entry,
      ["address", "controller_id", "signature"],
      `review signature ${index}`,
    );
    const signer = address(signature.address, `review signature ${index} address`);
    if (!CONTROLLER.test(signature.controller_id)
      || approvedByAddress.get(signer) !== signature.controller_id
      || !reviewerAuthority.approved_reviewer_hashes.includes(
        executionPolicyReviewerHash(signer),
      )) {
      fail("review signer is outside the injected reviewer authority");
    }
    return {
      address: signer,
      controller_id: signature.controller_id,
      signature: normalizeLowSSignature(
        signature.signature,
        `review signature ${index}`,
      ),
    };
  });
  if (signatures[0].address >= signatures[1].address
    || signatures[0].controller_id === signatures[1].controller_id) {
    fail("review signatures must use sorted independent signers and controllers");
  }
  if (typeof verifyReviewSignatures !== "function") {
    fail("an explicit historical review signature verifier is required");
  }
  const verification = verifyReviewSignatures(Object.freeze({
    signatures: deepFreezeCanonicalPlainDataGraph(signatures),
    message: `${RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX}${signingPayloadSha256}`,
    reviewerAuthority,
    signatureScheme: RELEASE_AUTHORITY_SIGNATURE_SCHEME,
    signatureVerifier: deepFreezeCanonicalPlainDataGraph(
      structuredClone(expectedSignatureVerifier),
    ),
  }));
  if (verification !== true) {
    fail("historical review signature verifier did not affirm both signatures");
  }
  return {
    schema: parsed.schema,
    stage: parsed.stage,
    subject_kind: parsed.subject_kind,
    release_sha: parsed.release_sha,
    chain_id: parsed.chain_id,
    subject_sha256: parsed.subject_sha256,
    dependencies: normalizedDependencies,
    reviewer_authority_genesis_sha256:
      parsed.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      parsed.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      parsed.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      parsed.reviewer_authority_current_status_sha256,
    approved_reviewer_hashes: [...parsed.approved_reviewer_hashes],
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: parsed.reviewer_set_sha256,
    signed_at: parsed.signed_at,
    expires_at: parsed.expires_at,
    signature_scheme: parsed.signature_scheme,
    signature_verifier: structuredClone(parsed.signature_verifier),
    signing_payload_sha256: signingPayloadSha256,
    signatures,
  };
}

function normalizeStageOneBody(value, expectedToolchain) {
  const parsed = exactRecord(value, [
    "ceremony_ledger_initialization", "ceremony_transaction_plan",
    "cvm_bootstrap_authorization_receipt_sha256", "cvm_launch_intent_sha256",
    "deployment_authority", "lock_protocol", "network",
    "pre_ceremony_runtime_authority_sha256", "release_sha", "schema",
    "status", "truth_status",
  ], "historical ceremony authorization body");
  exactString(parsed.schema, CEREMONY_AUTHORIZATION_CORE_SCHEMA, "ceremony schema");
  exactString(parsed.status, CEREMONY_AUTHORIZATION_CORE_STATUS, "ceremony status");
  exactString(
    parsed.truth_status,
    "pre_ceremony_authorization_not_finalized_ceremony_or_live_activation",
    "ceremony truth status",
  );
  const releaseSha = fixed(parsed.release_sha, SHA40, "ceremony release SHA");
  const deployment = exactRecord(parsed.deployment_authority, [
    "deployment_intent_sha256", "fresh_contract_deployment_receipt_sha256",
    "immutable_deployment_manifest",
    "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_genesis_sha256", "toolchain",
  ], "ceremony deployment authority");
  const manifest = exactRecord(deployment.immutable_deployment_manifest, [
    "bytes", "mode", "path", "schema_version", "sha256",
  ], "immutable deployment manifest");
  const normalizedManifest = {
    path: canonicalAbsolutePath(manifest.path, "immutable deployment manifest path"),
    sha256: sha256(manifest.sha256, "immutable deployment manifest digest"),
    bytes: integer(manifest.bytes, "immutable deployment manifest bytes", 2, MAX_BYTES),
    mode: integer(manifest.mode, "immutable deployment manifest mode", 0o444, 0o444),
    schema_version: integer(manifest.schema_version, "immutable deployment manifest schema", 2, 2),
  };
  const toolchain = normalizeExpectedToolchain(deployment.toolchain);
  if (!same(toolchain, expectedToolchain)) {
    fail("deployment toolchain differs from the injected toolchain authority");
  }
  const ledger = exactRecord(parsed.ceremony_ledger_initialization, [
    "initialization_receipt_path", "initialization_receipt_sha256",
    "ledger_initial_bytes", "ledger_initial_sha256", "ledger_mode",
    "ledger_path", "lock_protocol", "source_manifest_sha256",
  ], "ceremony ledger initialization");
  const normalizedLedger = {
    initialization_receipt_path: canonicalAbsolutePath(
      ledger.initialization_receipt_path,
      "ceremony ledger initialization receipt path",
    ),
    initialization_receipt_sha256: sha256(
      ledger.initialization_receipt_sha256,
      "ceremony ledger initialization receipt digest",
    ),
    ledger_path: canonicalAbsolutePath(ledger.ledger_path, "ceremony ledger path"),
    ledger_initial_sha256: sha256(
      ledger.ledger_initial_sha256,
      "initial ceremony ledger digest",
    ),
    ledger_initial_bytes: integer(
      ledger.ledger_initial_bytes,
      "initial ceremony ledger bytes",
      2,
      MAX_BYTES,
    ),
    ledger_mode: integer(ledger.ledger_mode, "ceremony ledger mode", 0o600, 0o600),
    source_manifest_sha256: sha256(
      ledger.source_manifest_sha256,
      "ceremony ledger source digest",
    ),
    lock_protocol: exactString(
      ledger.lock_protocol,
      RELEASE_CEREMONY_LOCK_PROTOCOL,
      "ceremony ledger lock protocol",
    ),
  };
  if (normalizedLedger.source_manifest_sha256 !== normalizedManifest.sha256
    || normalizedLedger.ledger_initial_sha256 !== normalizedManifest.sha256
    || normalizedLedger.ledger_initial_bytes !== normalizedManifest.bytes
    || normalizedLedger.ledger_path === normalizedManifest.path) {
    fail("ceremony ledger initialization is not the exact separate manifest copy");
  }
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    release_sha: releaseSha,
    network: network(parsed.network, "ceremony network"),
    deployment_authority: {
      deployment_intent_sha256: sha256(
        deployment.deployment_intent_sha256,
        "deployment intent digest",
      ),
      reviewer_authority_genesis_sha256: sha256(
        deployment.reviewer_authority_genesis_sha256,
        "reviewer authority genesis digest",
      ),
      reviewer_authority_genesis_acceptance_sha256: sha256(
        deployment.reviewer_authority_genesis_acceptance_sha256,
        "reviewer authority genesis acceptance digest",
      ),
      fresh_contract_deployment_receipt_sha256: sha256(
        deployment.fresh_contract_deployment_receipt_sha256,
        "fresh contract deployment receipt digest",
      ),
      immutable_deployment_manifest: normalizedManifest,
      toolchain,
    },
    cvm_launch_intent_sha256: sha256(
      parsed.cvm_launch_intent_sha256,
      "CVM launch intent digest",
    ),
    cvm_bootstrap_authorization_receipt_sha256: sha256(
      parsed.cvm_bootstrap_authorization_receipt_sha256,
      "signed-A non-live bootstrap authorization receipt digest",
    ),
    pre_ceremony_runtime_authority_sha256: sha256(
      parsed.pre_ceremony_runtime_authority_sha256,
      "pre-ceremony runtime authority digest",
    ),
    ceremony_ledger_initialization: normalizedLedger,
    ceremony_transaction_plan: normalizeTransactionPlan(
      parsed.ceremony_transaction_plan,
      releaseSha,
    ),
    lock_protocol: exactString(
      parsed.lock_protocol,
      RELEASE_CEREMONY_LOCK_PROTOCOL,
      "ceremony lock protocol",
    ),
  };
}

function stageOneDependencies(body) {
  const map = {
    deployment_intent: body.deployment_authority.deployment_intent_sha256,
    reviewer_authority_genesis:
      body.deployment_authority.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance:
      body.deployment_authority.reviewer_authority_genesis_acceptance_sha256,
    fresh_contract_deployment_receipt:
      body.deployment_authority.fresh_contract_deployment_receipt_sha256,
    immutable_deployment_manifest:
      body.deployment_authority.immutable_deployment_manifest.sha256,
    ceremony_ledger_initialization_receipt:
      body.ceremony_ledger_initialization.initialization_receipt_sha256,
    ceremony_ledger_initial:
      body.ceremony_ledger_initialization.ledger_initial_sha256,
    ceremony_transaction_plan: body.ceremony_transaction_plan.plan_sha256,
    cvm_launch_intent: body.cvm_launch_intent_sha256,
    cvm_nonlive_bootstrap_authorization_receipt:
      body.cvm_bootstrap_authorization_receipt_sha256,
    pre_ceremony_runtime_authority:
      body.pre_ceremony_runtime_authority_sha256,
  };
  return STAGE_ONE_DEPENDENCY_KINDS.map((kind) => ({
    kind,
    sha256: map[kind],
  }));
}

export function normalizeHistoricalCeremonyExpectedContext(value) {
  assertBoundedCanonicalGraph(value, "historical ceremony expected context");
  const parsed = exactRecord(value, [
    "cvm_launch_intent_sha256", "deployment_intent_sha256",
    "fresh_contract_deployment_receipt_sha256",
    "activation_evidence_lease_expires_at",
    "pre_ceremony_runtime_authority_sha256",
    "release_sha", "runtime_authority_issued_at",
    "signed_a_bootstrap_authorization_receipt_sha256", "toolchain",
  ], "historical ceremony expected context");
  const issuedAt = integer(
    parsed.runtime_authority_issued_at,
    "runtime authority issued_at",
    1,
  );
  const expiresAt = integer(
    parsed.activation_evidence_lease_expires_at,
    "runtime authority activation-evidence lease expiry",
    issuedAt + 1,
  );
  return deepFreezeCanonicalPlainDataGraph({
    release_sha: fixed(parsed.release_sha, SHA40, "historical release SHA"),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "historical deployment intent digest",
    ),
    fresh_contract_deployment_receipt_sha256: sha256(
      parsed.fresh_contract_deployment_receipt_sha256,
      "historical fresh contract deployment receipt digest",
    ),
    cvm_launch_intent_sha256: sha256(
      parsed.cvm_launch_intent_sha256,
      "historical CVM launch intent digest",
    ),
    signed_a_bootstrap_authorization_receipt_sha256: sha256(
      parsed.signed_a_bootstrap_authorization_receipt_sha256,
      "reconstructed signed-A receipt digest",
    ),
    pre_ceremony_runtime_authority_sha256: sha256(
      parsed.pre_ceremony_runtime_authority_sha256,
      "historical pre-ceremony runtime authority digest",
    ),
    runtime_authority_issued_at: issuedAt,
    activation_evidence_lease_expires_at: expiresAt,
    toolchain: normalizeExpectedToolchain(parsed.toolchain),
  }, { label: "normalized historical ceremony expected context" });
}

export function projectHistoricalCeremonyExpectedContext({
  runtimeAuthority,
  runtimeAuthoritySha256,
  freshContractDeploymentReceiptSha256,
  signedABootstrapAuthorizationReceiptSha256,
  toolchain,
} = {}) {
  assertBoundedCanonicalGraph(
    runtimeAuthority,
    "projected historical ceremony runtime authority",
  );
  if (!isRecord(runtimeAuthority)) {
    fail("projected historical ceremony runtime authority must be normalized R");
  }
  return normalizeHistoricalCeremonyExpectedContext({
    release_sha: runtimeAuthority.release_sha,
    deployment_intent_sha256: runtimeAuthority.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      freshContractDeploymentReceiptSha256,
    cvm_launch_intent_sha256: runtimeAuthority.cvm_launch_intent_sha256,
    signed_a_bootstrap_authorization_receipt_sha256:
      signedABootstrapAuthorizationReceiptSha256,
    pre_ceremony_runtime_authority_sha256: runtimeAuthoritySha256,
    runtime_authority_issued_at: runtimeAuthority.issued_at,
    activation_evidence_lease_expires_at:
      runtimeAuthority.activation_evidence_lease_expires_at,
    toolchain,
  });
}

export function historicalCeremonyAuthorizationReviewSubjectSha256(
  value,
  { expectedContext } = {},
) {
  const context = normalizeHistoricalCeremonyExpectedContext(expectedContext);
  return domainDigest(
    CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_DOMAIN,
    normalizeStageOneBody(value, context.toolchain),
  );
}

export function historicalCeremonyAuthorizationReviewSigningPayload(
  unsignedBody,
  reviewMetadata,
  { expectedContext, reviewerAuthority, expectedSignatureVerifier } = {},
) {
  const context = normalizeHistoricalCeremonyExpectedContext(expectedContext);
  const authority = normalizeHistoricalReviewerAuthority(reviewerAuthority);
  const body = normalizeStageOneBody(unsignedBody, context.toolchain);
  return normalizeHistoricalReviewSigningPayload({
    schema: RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA,
    stage: CEREMONY_AUTHORIZATION_CORE_STATUS,
    subject_kind: CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_KIND,
    release_sha: body.release_sha,
    chain_id: CHAIN_ID,
    subject_sha256: domainDigest(
      CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_DOMAIN,
      body,
    ),
    dependencies: stageOneDependencies(body),
    reviewer_authority_genesis_sha256:
      authority.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      authority.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      authority.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      authority.reviewer_authority_current_status_sha256,
    approved_reviewer_hashes: authority.approved_reviewer_hashes,
    reviewer_root_hash: authority.reviewer_root_hash,
    reviewer_set_sha256: authority.reviewer_set_sha256,
    ...reviewMetadata,
    signature_scheme: RELEASE_AUTHORITY_SIGNATURE_SCHEME,
    signature_verifier: expectedSignatureVerifier,
  }, { expectedSignatureVerifier });
}

export function normalizeHistoricalCeremonyAuthorizationCore(value, {
  expectedContext,
  reviewerAuthority,
  expectedSignatureVerifier,
  verifyReviewSignatures,
} = {}) {
  assertBoundedCanonicalGraph(value, "historical ceremony authorization core");
  const context = normalizeHistoricalCeremonyExpectedContext(expectedContext);
  const authority = normalizeHistoricalReviewerAuthority(reviewerAuthority);
  const parsed = exactRecord(value, [
    "ceremony_ledger_initialization", "ceremony_transaction_plan",
    "cvm_bootstrap_authorization_receipt_sha256", "cvm_launch_intent_sha256",
    "deployment_authority", "lock_protocol", "network",
    "pre_ceremony_runtime_authority_sha256", "release_sha", "review",
    "schema", "status", "truth_status",
  ], "historical ceremony authorization core");
  const body = normalizeStageOneBody(
    Object.fromEntries(Object.entries(parsed).filter(([key]) => key !== "review")),
    context.toolchain,
  );
  if (body.release_sha !== context.release_sha
    || body.deployment_authority.deployment_intent_sha256
      !== context.deployment_intent_sha256
    || body.deployment_authority.fresh_contract_deployment_receipt_sha256
      !== context.fresh_contract_deployment_receipt_sha256
    || body.deployment_authority.reviewer_authority_genesis_sha256
      !== authority.reviewer_authority_genesis_sha256
    || body.deployment_authority.reviewer_authority_genesis_acceptance_sha256
      !== authority.reviewer_authority_genesis_acceptance_sha256
    || body.cvm_launch_intent_sha256 !== context.cvm_launch_intent_sha256
    || body.cvm_bootstrap_authorization_receipt_sha256
      !== context.signed_a_bootstrap_authorization_receipt_sha256
    || body.pre_ceremony_runtime_authority_sha256
      !== context.pre_ceremony_runtime_authority_sha256) {
    fail("historical B drifted from deployment, signed-A, or reconstructed R authority");
  }
  const subjectSha256 = domainDigest(
    CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_DOMAIN,
    body,
  );
  const review = normalizeCryptographicReview(parsed.review, {
    stage: CEREMONY_AUTHORIZATION_CORE_STATUS,
    subjectKind: CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_KIND,
    subjectSha256,
    releaseSha: body.release_sha,
    dependencies: stageOneDependencies(body),
    reviewerAuthority: authority,
    expectedSignatureVerifier,
    verifyReviewSignatures,
  });
  const signedAtMs = millisecondTimestamp(review.signed_at, "B review signed_at");
  const expiresAtMs = millisecondTimestamp(review.expires_at, "B review expires_at");
  if (signedAtMs < context.runtime_authority_issued_at * 1_000
    || signedAtMs
      >= context.activation_evidence_lease_expires_at * 1_000
    || expiresAtMs
      > context.activation_evidence_lease_expires_at * 1_000) {
    fail("B review is outside the reconstructed R activation-evidence lease");
  }
  return deepFreezeCanonicalPlainDataGraph(
    { ...body, review },
    { label: "normalized historical ceremony authorization" },
  );
}

export function historicalCeremonyAuthorizationCoreSha256(value, options) {
  return domainDigest(
    CEREMONY_AUTHORIZATION_CORE_DOMAIN,
    normalizeHistoricalCeremonyAuthorizationCore(value, options),
  );
}

export function normalizeHistoricalCeremonyTransactionRpcObservation(value) {
  const parsed = exactRecord(value, [
    "access_list_sha256", "block_hash", "block_number", "chain_id", "from",
    "gas_limit", "input_sha256", "max_fee_per_gas_wei",
    "max_priority_fee_per_gas_wei", "nonce", "schema", "to",
    "transaction_hash", "transaction_index", "transaction_type", "value_wei",
  ], "historical ceremony transaction RPC observation");
  exactString(
    parsed.schema,
    CEREMONY_TRANSACTION_RPC_OBSERVATION_SCHEMA,
    "ceremony transaction observation schema",
  );
  integer(parsed.chain_id, "ceremony transaction chain ID", CHAIN_ID, CHAIN_ID);
  integer(parsed.transaction_type, "ceremony transaction type", 2, 2);
  const gasLimit = decimal(parsed.gas_limit, "ceremony transaction gas limit");
  const maxFee = decimal(
    parsed.max_fee_per_gas_wei,
    "ceremony transaction max fee",
  );
  const maxPriorityFee = decimal(
    parsed.max_priority_fee_per_gas_wei,
    "ceremony transaction max priority fee",
  );
  if (BigInt(gasLimit) === 0n || BigInt(maxFee) === 0n
    || BigInt(maxPriorityFee) > BigInt(maxFee)) {
    fail("ceremony transaction gas and fee bounds are invalid");
  }
  return {
    schema: parsed.schema,
    chain_id: parsed.chain_id,
    transaction_hash: bytes32(parsed.transaction_hash, "ceremony transaction hash"),
    block_number: integer(parsed.block_number, "ceremony transaction block number", 1),
    block_hash: bytes32(parsed.block_hash, "ceremony transaction block hash"),
    transaction_index: integer(parsed.transaction_index, "ceremony transaction index"),
    from: address(parsed.from, "ceremony transaction signer"),
    to: address(parsed.to, "ceremony transaction destination"),
    nonce: decimal(parsed.nonce, "ceremony transaction nonce"),
    value_wei: decimal(parsed.value_wei, "ceremony transaction value"),
    input_sha256: sha256(parsed.input_sha256, "ceremony transaction calldata"),
    gas_limit: gasLimit,
    transaction_type: parsed.transaction_type,
    max_fee_per_gas_wei: maxFee,
    max_priority_fee_per_gas_wei: maxPriorityFee,
    access_list_sha256: sha256(
      parsed.access_list_sha256,
      "ceremony transaction access list",
    ),
  };
}

export function historicalCeremonyTransactionRpcObservationSha256(value) {
  return domainDigest(
    CEREMONY_TRANSACTION_RPC_OBSERVATION_DOMAIN,
    normalizeHistoricalCeremonyTransactionRpcObservation(value),
  );
}

function normalizeReceiptLog(value, index) {
  const parsed = exactRecord(
    value,
    ["address", "data", "log_index", "removed", "topics"],
    `historical ceremony receipt log ${index}`,
  );
  if (parsed.removed !== false || !Array.isArray(parsed.topics)
    || parsed.topics.length > 4) {
    fail(`historical ceremony receipt log ${index} is invalid`);
  }
  if (!HEX_DATA.test(parsed.data) || (parsed.data.length - 2) / 2 > 65_536) {
    fail(`historical ceremony receipt log ${index} data is invalid`);
  }
  return {
    address: address(parsed.address, `ceremony receipt log ${index} address`),
    topics: parsed.topics.map((entry, topicIndex) => bytes32(
      entry,
      `ceremony receipt log ${index} topic ${topicIndex}`,
    )),
    data: parsed.data,
    log_index: integer(parsed.log_index, `ceremony receipt log ${index} index`),
    removed: false,
  };
}

export function normalizeHistoricalCeremonyReceiptRpcObservation(value) {
  const parsed = exactRecord(value, [
    "block_hash", "block_number", "chain_id", "contract_address",
    "cumulative_gas_used", "effective_gas_price_wei", "from", "gas_used",
    "logs", "logs_bloom", "schema", "status", "to", "transaction_hash",
    "transaction_index", "transaction_type",
  ], "historical ceremony receipt RPC observation");
  exactString(
    parsed.schema,
    CEREMONY_RECEIPT_RPC_OBSERVATION_SCHEMA,
    "ceremony receipt observation schema",
  );
  integer(parsed.chain_id, "ceremony receipt chain ID", CHAIN_ID, CHAIN_ID);
  integer(parsed.transaction_type, "ceremony receipt transaction type", 2, 2);
  integer(parsed.status, "ceremony receipt status", 1, 1);
  const contractAddress = address(
    parsed.contract_address,
    "ceremony receipt contract address",
    { allowZero: true },
  );
  if (contractAddress !== ZERO_ADDRESS) {
    fail("ceremony configuration receipts must not create contracts");
  }
  const cumulativeGasUsed = decimal(
    parsed.cumulative_gas_used,
    "ceremony receipt cumulative gas used",
  );
  const gasUsed = decimal(parsed.gas_used, "ceremony receipt gas used");
  const effectiveGasPrice = decimal(
    parsed.effective_gas_price_wei,
    "ceremony receipt effective gas price",
  );
  if (BigInt(gasUsed) === 0n || BigInt(cumulativeGasUsed) < BigInt(gasUsed)
    || BigInt(effectiveGasPrice) === 0n) {
    fail("ceremony receipt gas observations are invalid");
  }
  if (!Array.isArray(parsed.logs) || parsed.logs.length > 256) {
    fail("ceremony receipt logs exceed the exact bound");
  }
  const logs = parsed.logs.map(normalizeReceiptLog);
  for (let index = 1; index < logs.length; index += 1) {
    if (logs[index].log_index <= logs[index - 1].log_index) {
      fail("ceremony receipt logs must be strictly ordered by log index");
    }
  }
  fixed(parsed.logs_bloom, LOGS_BLOOM, "ceremony receipt logs bloom");
  return {
    schema: parsed.schema,
    chain_id: parsed.chain_id,
    transaction_hash: bytes32(
      parsed.transaction_hash,
      "ceremony receipt transaction hash",
    ),
    block_number: integer(parsed.block_number, "ceremony receipt block number", 1),
    block_hash: bytes32(parsed.block_hash, "ceremony receipt block hash"),
    transaction_index: integer(parsed.transaction_index, "ceremony receipt transaction index"),
    from: address(parsed.from, "ceremony receipt signer"),
    to: address(parsed.to, "ceremony receipt destination"),
    contract_address: contractAddress,
    status: parsed.status,
    transaction_type: parsed.transaction_type,
    cumulative_gas_used: cumulativeGasUsed,
    gas_used: gasUsed,
    effective_gas_price_wei: effectiveGasPrice,
    logs_bloom: parsed.logs_bloom,
    logs,
  };
}

export function historicalCeremonyReceiptRpcObservationSha256(value) {
  return domainDigest(
    CEREMONY_RECEIPT_RPC_OBSERVATION_DOMAIN,
    normalizeHistoricalCeremonyReceiptRpcObservation(value),
  );
}

export function normalizeHistoricalCommonFinalizedBlockRpcObservation(value) {
  const parsed = exactRecord(value, [
    "base_fee_per_gas_wei", "block_hash", "block_number", "block_timestamp",
    "chain_id", "gas_limit", "gas_used", "parent_hash", "receipts_root",
    "schema", "state_root", "transactions_root",
  ], "historical finalized block RPC observation");
  exactString(
    parsed.schema,
    COMMON_FINALIZED_BLOCK_RPC_OBSERVATION_SCHEMA,
    "finalized block observation schema",
  );
  integer(parsed.chain_id, "finalized block chain ID", CHAIN_ID, CHAIN_ID);
  const gasLimit = decimal(parsed.gas_limit, "finalized block gas limit");
  const gasUsed = decimal(parsed.gas_used, "finalized block gas used");
  const baseFee = decimal(parsed.base_fee_per_gas_wei, "finalized block base fee");
  if (BigInt(gasLimit) === 0n || BigInt(gasUsed) > BigInt(gasLimit)
    || BigInt(baseFee) === 0n) {
    fail("finalized block gas observations are invalid");
  }
  return {
    schema: parsed.schema,
    chain_id: parsed.chain_id,
    block_number: integer(parsed.block_number, "finalized block number", 1),
    block_hash: bytes32(parsed.block_hash, "finalized block hash"),
    parent_hash: bytes32(parsed.parent_hash, "finalized block parent hash"),
    block_timestamp: integer(parsed.block_timestamp, "finalized block timestamp", 1),
    state_root: bytes32(parsed.state_root, "finalized block state root"),
    transactions_root: bytes32(
      parsed.transactions_root,
      "finalized block transactions root",
    ),
    receipts_root: bytes32(parsed.receipts_root, "finalized block receipts root"),
    gas_limit: gasLimit,
    gas_used: gasUsed,
    base_fee_per_gas_wei: baseFee,
  };
}

export function historicalCommonFinalizedBlockRpcObservationSha256(value) {
  return domainDigest(
    COMMON_FINALIZED_BLOCK_RPC_OBSERVATION_DOMAIN,
    normalizeHistoricalCommonFinalizedBlockRpcObservation(value),
  );
}

function normalizeCommonFinalizedState(value) {
  const parsed = exactRecord(value, [
    "canonical_state_sha256", "independent_rpc_count",
    "latest_state_recheck_sha256", "primary_rpc_block",
    "primary_rpc_block_sha256", "primary_rpc_id_sha256",
    "primary_state_sha256", "secondary_rpc_block",
    "secondary_rpc_block_sha256", "secondary_rpc_id_sha256",
    "secondary_state_sha256",
  ], "historical common finalized state");
  const primaryId = sha256(parsed.primary_rpc_id_sha256, "primary RPC identity");
  const secondaryId = sha256(parsed.secondary_rpc_id_sha256, "secondary RPC identity");
  if (primaryId === secondaryId) {
    fail("common finalized state requires two independent RPC identities");
  }
  const primaryBlock = normalizeHistoricalCommonFinalizedBlockRpcObservation(
    parsed.primary_rpc_block,
  );
  const secondaryBlock = normalizeHistoricalCommonFinalizedBlockRpcObservation(
    parsed.secondary_rpc_block,
  );
  const primaryBlockSha256 =
    historicalCommonFinalizedBlockRpcObservationSha256(primaryBlock);
  const secondaryBlockSha256 =
    historicalCommonFinalizedBlockRpcObservationSha256(secondaryBlock);
  if (parsed.primary_rpc_block_sha256 !== primaryBlockSha256
    || parsed.secondary_rpc_block_sha256 !== secondaryBlockSha256
    || primaryBlockSha256 !== secondaryBlockSha256) {
    fail("independent RPC finalized block observations disagree or have invalid digests");
  }
  const primaryStateSha256 = sha256(
    parsed.primary_state_sha256,
    "primary finalized state",
  );
  const secondaryStateSha256 = sha256(
    parsed.secondary_state_sha256,
    "secondary finalized state",
  );
  const canonicalStateSha256 = sha256(
    parsed.canonical_state_sha256,
    "canonical finalized state",
  );
  if (primaryStateSha256 !== secondaryStateSha256
    || primaryStateSha256 !== canonicalStateSha256) {
    fail("independent RPC common finalized state observations disagree");
  }
  return {
    independent_rpc_count: integer(
      parsed.independent_rpc_count,
      "independent RPC count",
      2,
      2,
    ),
    primary_rpc_id_sha256: primaryId,
    secondary_rpc_id_sha256: secondaryId,
    primary_rpc_block: primaryBlock,
    primary_rpc_block_sha256: primaryBlockSha256,
    secondary_rpc_block: secondaryBlock,
    secondary_rpc_block_sha256: secondaryBlockSha256,
    primary_state_sha256: primaryStateSha256,
    secondary_state_sha256: secondaryStateSha256,
    canonical_state_sha256: canonicalStateSha256,
    latest_state_recheck_sha256: sha256(
      parsed.latest_state_recheck_sha256,
      "latest state recheck",
    ),
  };
}

function normalizeCeremonyTransactionEvidence(value, index, plan, commonState) {
  const parsed = exactRecord(value, [
    "primary_rpc_block", "primary_rpc_block_sha256", "primary_rpc_receipt",
    "primary_rpc_id_sha256", "primary_rpc_receipt_sha256",
    "primary_rpc_transaction", "primary_rpc_transaction_sha256",
    "secondary_rpc_block", "secondary_rpc_block_sha256",
    "secondary_rpc_id_sha256", "secondary_rpc_receipt",
    "secondary_rpc_receipt_sha256", "secondary_rpc_transaction",
    "secondary_rpc_transaction_sha256", "sequence", "writer_id",
  ], `historical ceremony transaction evidence ${index}`);
  const planned = plan.transactions[index];
  if (!planned || parsed.sequence !== index || parsed.writer_id !== planned.writer_id) {
    fail(`ceremony transaction evidence ${index} differs from signed B`);
  }
  const primaryRpcId = sha256(
    parsed.primary_rpc_id_sha256,
    `ceremony transaction ${index} primary RPC identity`,
  );
  const secondaryRpcId = sha256(
    parsed.secondary_rpc_id_sha256,
    `ceremony transaction ${index} secondary RPC identity`,
  );
  if (primaryRpcId === secondaryRpcId
    || primaryRpcId !== commonState.primary_rpc_id_sha256
    || secondaryRpcId !== commonState.secondary_rpc_id_sha256) {
    fail(`ceremony transaction ${index} does not use the common RPC authority`);
  }
  const primaryTransaction = normalizeHistoricalCeremonyTransactionRpcObservation(
    parsed.primary_rpc_transaction,
  );
  const secondaryTransaction = normalizeHistoricalCeremonyTransactionRpcObservation(
    parsed.secondary_rpc_transaction,
  );
  const primaryReceipt = normalizeHistoricalCeremonyReceiptRpcObservation(
    parsed.primary_rpc_receipt,
  );
  const secondaryReceipt = normalizeHistoricalCeremonyReceiptRpcObservation(
    parsed.secondary_rpc_receipt,
  );
  const primaryBlock = normalizeHistoricalCommonFinalizedBlockRpcObservation(
    parsed.primary_rpc_block,
  );
  const secondaryBlock = normalizeHistoricalCommonFinalizedBlockRpcObservation(
    parsed.secondary_rpc_block,
  );
  const primaryTransactionSha256 =
    historicalCeremonyTransactionRpcObservationSha256(primaryTransaction);
  const secondaryTransactionSha256 =
    historicalCeremonyTransactionRpcObservationSha256(secondaryTransaction);
  const primaryReceiptSha256 =
    historicalCeremonyReceiptRpcObservationSha256(primaryReceipt);
  const secondaryReceiptSha256 =
    historicalCeremonyReceiptRpcObservationSha256(secondaryReceipt);
  const primaryBlockSha256 =
    historicalCommonFinalizedBlockRpcObservationSha256(primaryBlock);
  const secondaryBlockSha256 =
    historicalCommonFinalizedBlockRpcObservationSha256(secondaryBlock);
  if (parsed.primary_rpc_transaction_sha256 !== primaryTransactionSha256
    || parsed.secondary_rpc_transaction_sha256 !== secondaryTransactionSha256
    || parsed.primary_rpc_receipt_sha256 !== primaryReceiptSha256
    || parsed.secondary_rpc_receipt_sha256 !== secondaryReceiptSha256
    || parsed.primary_rpc_block_sha256 !== primaryBlockSha256
    || parsed.secondary_rpc_block_sha256 !== secondaryBlockSha256
    || primaryTransactionSha256 !== secondaryTransactionSha256
    || primaryReceiptSha256 !== secondaryReceiptSha256
    || primaryBlockSha256 !== secondaryBlockSha256) {
    fail(`ceremony transaction ${index} independent RPC observations disagree`);
  }
  if (primaryTransaction.from !== planned.signer_address
    || primaryTransaction.nonce !== planned.nonce
    || primaryTransaction.to !== planned.to
    || primaryTransaction.value_wei !== planned.value_wei
    || primaryTransaction.input_sha256 !== planned.calldata_sha256) {
    fail(`ceremony transaction ${index} differs from its signed B plan entry`);
  }
  if (primaryReceipt.transaction_hash !== primaryTransaction.transaction_hash
    || primaryReceipt.block_number !== primaryTransaction.block_number
    || primaryReceipt.block_hash !== primaryTransaction.block_hash
    || primaryReceipt.transaction_index !== primaryTransaction.transaction_index
    || primaryReceipt.from !== primaryTransaction.from
    || primaryReceipt.to !== primaryTransaction.to
    || primaryReceipt.transaction_type !== primaryTransaction.transaction_type
    || primaryBlock.block_number !== primaryTransaction.block_number
    || primaryBlock.block_hash !== primaryTransaction.block_hash) {
    fail(`ceremony transaction ${index} transaction, receipt, and block disagree`);
  }
  return {
    sequence: index,
    writer_id: parsed.writer_id,
    primary_rpc_id_sha256: primaryRpcId,
    secondary_rpc_id_sha256: secondaryRpcId,
    primary_rpc_transaction: primaryTransaction,
    primary_rpc_transaction_sha256: primaryTransactionSha256,
    secondary_rpc_transaction: secondaryTransaction,
    secondary_rpc_transaction_sha256: secondaryTransactionSha256,
    primary_rpc_receipt: primaryReceipt,
    primary_rpc_receipt_sha256: primaryReceiptSha256,
    secondary_rpc_receipt: secondaryReceipt,
    secondary_rpc_receipt_sha256: secondaryReceiptSha256,
    primary_rpc_block: primaryBlock,
    primary_rpc_block_sha256: primaryBlockSha256,
    secondary_rpc_block: secondaryBlock,
    secondary_rpc_block_sha256: secondaryBlockSha256,
  };
}

function normalizeContractEntries(value) {
  if (!Array.isArray(value) || value.length !== RELEASE_CONTRACT_STATE_KEYS.length) {
    fail("contract state must contain the exact seven-contract suite");
  }
  const contracts = value.map((entry, index) => {
    const contract = exactRecord(entry, [
      "address", "configuration_sha256", "contract_key", "control_address",
      "control_role", "runtime_code_hash",
    ], `historical contract state ${index}`);
    const key = RELEASE_CONTRACT_STATE_KEYS[index];
    exactString(contract.contract_key, key, `contract state ${index} key`);
    exactString(
      contract.control_role,
      CONTROL_ROLE_BY_CONTRACT[key],
      `contract state ${key} control role`,
    );
    const allowZero = key === "royalty_distributor";
    const controlAddress = address(
      contract.control_address,
      `${key} control address`,
      { allowZero },
    );
    if (allowZero !== (controlAddress === ZERO_ADDRESS)) {
      fail("RoyaltyDistributor alone must use immutable_no_owner and zero control");
    }
    return {
      contract_key: key,
      address: address(contract.address, `${key} address`),
      runtime_code_hash: bytes32(contract.runtime_code_hash, `${key} runtime code hash`),
      control_role: contract.control_role,
      control_address: controlAddress,
      configuration_sha256: sha256(
        contract.configuration_sha256,
        `${key} configuration digest`,
      ),
    };
  });
  if (new Set(contracts.map((entry) => entry.address)).size !== contracts.length) {
    fail("contract state addresses must be distinct");
  }
  return contracts;
}

export function normalizeHistoricalExecutionPolicyAnchorRpcRead(value) {
  const parsed = exactRecord(value, [
    "block_hash", "block_number", "chain_id", "contract_address",
    "deployment_intent_sha256_bytes32",
    "reviewer_authority_genesis_acceptance_sha256_bytes32", "schema",
  ], "historical ExecutionPolicyAnchor RPC read");
  exactString(
    parsed.schema,
    EXECUTION_POLICY_ANCHOR_RPC_READ_SCHEMA,
    "ExecutionPolicyAnchor RPC read schema",
  );
  return {
    schema: parsed.schema,
    chain_id: integer(parsed.chain_id, "anchor read chain ID", CHAIN_ID, CHAIN_ID),
    contract_address: address(parsed.contract_address, "anchor read address"),
    block_number: integer(parsed.block_number, "anchor read block number", 1),
    block_hash: bytes32(parsed.block_hash, "anchor read block hash"),
    deployment_intent_sha256_bytes32: bytes32(
      parsed.deployment_intent_sha256_bytes32,
      "anchor deployment intent commitment",
    ),
    reviewer_authority_genesis_acceptance_sha256_bytes32: bytes32(
      parsed.reviewer_authority_genesis_acceptance_sha256_bytes32,
      "anchor reviewer genesis acceptance commitment",
    ),
  };
}

export function historicalExecutionPolicyAnchorRpcReadSha256(value) {
  return domainDigest(
    EXECUTION_POLICY_ANCHOR_RPC_READ_DOMAIN,
    normalizeHistoricalExecutionPolicyAnchorRpcRead(value),
  );
}

function normalizeExecutionPolicyAnchorCommitment(value, {
  contracts,
  deploymentIntentSha256,
  reviewerGenesisAcceptanceSha256,
  commonFinalizedState,
}) {
  const parsed = exactRecord(value, [
    "primary_rpc_read", "primary_rpc_read_sha256", "secondary_rpc_read",
    "secondary_rpc_read_sha256",
  ], "historical ExecutionPolicyAnchor commitment");
  const primaryRead = normalizeHistoricalExecutionPolicyAnchorRpcRead(
    parsed.primary_rpc_read,
  );
  const secondaryRead = normalizeHistoricalExecutionPolicyAnchorRpcRead(
    parsed.secondary_rpc_read,
  );
  const primarySha256 = historicalExecutionPolicyAnchorRpcReadSha256(primaryRead);
  const secondarySha256 = historicalExecutionPolicyAnchorRpcReadSha256(secondaryRead);
  if (parsed.primary_rpc_read_sha256 !== primarySha256
    || parsed.secondary_rpc_read_sha256 !== secondarySha256
    || primarySha256 !== secondarySha256) {
    fail("ExecutionPolicyAnchor independent reads disagree or have invalid digests");
  }
  const anchor = contracts.find(
    (entry) => entry.contract_key === "execution_policy_anchor",
  );
  if (primaryRead.contract_address !== anchor.address
    || primaryRead.deployment_intent_sha256_bytes32
      !== `0x${deploymentIntentSha256.slice(7)}`
    || primaryRead.reviewer_authority_genesis_acceptance_sha256_bytes32
      !== `0x${reviewerGenesisAcceptanceSha256.slice(7)}`
    || (commonFinalizedState && (
      primaryRead.block_number
        !== commonFinalizedState.primary_rpc_block.block_number
      || primaryRead.block_hash
        !== commonFinalizedState.primary_rpc_block.block_hash
    ))) {
    fail("ExecutionPolicyAnchor read differs from signed deployment authority or final block");
  }
  return {
    primary_rpc_read: primaryRead,
    primary_rpc_read_sha256: primarySha256,
    secondary_rpc_read: secondaryRead,
    secondary_rpc_read_sha256: secondarySha256,
  };
}

function contractConfigurationSetPayload({
  contracts,
  challengeGenesisSha256,
  deploymentIntentSha256,
  reviewerGenesisAcceptanceSha256,
  executionPolicyAnchorCommitment,
}) {
  return {
    contracts,
    challenge_genesis_sha256: challengeGenesisSha256,
    deployment_intent_sha256: deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerGenesisAcceptanceSha256,
    execution_policy_anchor_commitment: executionPolicyAnchorCommitment,
  };
}

function normalizeContractState(value, {
  expectedDeploymentIntentSha256,
  expectedReviewerGenesisAcceptanceSha256,
  commonFinalizedState,
}) {
  const parsed = exactRecord(value, [
    "challenge_genesis_sha256", "configuration_set_sha256", "contracts",
    "deployment_intent_sha256", "execution_policy_anchor_commitment",
    "reviewer_authority_genesis_acceptance_sha256",
  ], "historical contract state");
  const contracts = normalizeContractEntries(parsed.contracts);
  const challengeGenesisSha256 = sha256(
    parsed.challenge_genesis_sha256,
    "challenge genesis digest",
  );
  const deploymentIntentSha256 = sha256(
    parsed.deployment_intent_sha256,
    "contract state deployment intent",
  );
  const reviewerGenesisAcceptanceSha256 = sha256(
    parsed.reviewer_authority_genesis_acceptance_sha256,
    "contract state reviewer genesis acceptance",
  );
  if (deploymentIntentSha256 !== expectedDeploymentIntentSha256
    || reviewerGenesisAcceptanceSha256
      !== expectedReviewerGenesisAcceptanceSha256) {
    fail("contract state deployment authority commitments drifted from B");
  }
  const executionPolicyAnchorCommitment =
    normalizeExecutionPolicyAnchorCommitment(
      parsed.execution_policy_anchor_commitment,
      {
        contracts,
        deploymentIntentSha256,
        reviewerGenesisAcceptanceSha256,
        commonFinalizedState,
      },
    );
  const configurationSetSha256 = domainDigest(
    "dnai-wikigen/live-contract-configuration-set/v2\0",
    contractConfigurationSetPayload({
      contracts,
      challengeGenesisSha256,
      deploymentIntentSha256,
      reviewerGenesisAcceptanceSha256,
      executionPolicyAnchorCommitment,
    }),
  );
  requireEqual(
    parsed.configuration_set_sha256,
    configurationSetSha256,
    "contract configuration set digest",
  );
  return {
    contracts,
    challenge_genesis_sha256: challengeGenesisSha256,
    deployment_intent_sha256: deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerGenesisAcceptanceSha256,
    execution_policy_anchor_commitment: executionPolicyAnchorCommitment,
    configuration_set_sha256: configurationSetSha256,
  };
}

function normalizeFinalCvms(value) {
  if (!Array.isArray(value) || value.length !== RELEASE_CVM_KEYS.length) {
    fail("final CVM state must contain the exact seven CVMs");
  }
  const cvms = value.map((entry, index) => {
    const parsed = exactRecord(entry, [
      "app_id", "attestation_evidence_sha256", "compose_hash_sha256",
      "cvm_id", "cvm_key", "tee_identity",
    ], `historical final CVM state ${index}`);
    exactString(parsed.cvm_key, RELEASE_CVM_KEYS[index], `final CVM ${index} key`);
    return {
      cvm_key: parsed.cvm_key,
      app_id: boundedIdentifier(parsed.app_id, `${parsed.cvm_key} app ID`),
      cvm_id: boundedIdentifier(parsed.cvm_id, `${parsed.cvm_key} CVM ID`),
      compose_hash_sha256: sha256(
        parsed.compose_hash_sha256,
        `${parsed.cvm_key} compose hash`,
      ),
      tee_identity: address(parsed.tee_identity, `${parsed.cvm_key} TEE identity`),
      attestation_evidence_sha256: sha256(
        parsed.attestation_evidence_sha256,
        `${parsed.cvm_key} attestation evidence`,
      ),
    };
  });
  for (const field of ["app_id", "cvm_id", "tee_identity"]) {
    if (new Set(cvms.map((entry) => entry[field])).size !== cvms.length) {
      fail(`final CVM ${field} values must be pairwise distinct`);
    }
  }
  return cvms;
}

function normalizeBrowserBinding(value) {
  const parsed = exactRecord(value, [
    "activation_signer_address", "app_id", "chain_id", "compose_hash",
    "ceremony_nonce", "cvm_id", "deployment_intent_sha256",
    "compute_vault_address", "compute_vault_runtime_code_hash",
    "fresh_contract_deployment_receipt_sha256", "max_verdict_age_seconds",
    "main_runtime_evidence_sha256", "measurement_policy_set_sha256",
    "measurement_policy_sha256", "os_image_hash", "qvl_release_policy_hash",
    "qvl_verifier", "release_authority_sha256", "revoked_quote_hashes",
  ], "historical compute-workload browser binding");
  if (!Array.isArray(parsed.revoked_quote_hashes)
    || parsed.revoked_quote_hashes.length > 256) {
    fail("browser revoked quote list is incomplete or unbounded");
  }
  const revoked = parsed.revoked_quote_hashes.map((entry, index) => bytes32(
    entry,
    `browser revoked quote hash ${index}`,
  ));
  if (new Set(revoked).size !== revoked.length
    || revoked.some((entry, index) => index > 0 && revoked[index - 1] >= entry)) {
    fail("browser revoked quote hashes must be strictly sorted and unique");
  }
  return {
    qvl_verifier: address(parsed.qvl_verifier, "browser QVL verifier"),
    qvl_release_policy_hash: bytes32(
      parsed.qvl_release_policy_hash,
      "browser QVL release policy hash",
    ),
    compose_hash: bytes32(parsed.compose_hash, "browser main runtime compose hash"),
    app_id: appId(parsed.app_id, "browser main runtime app ID"),
    os_image_hash: bareSha256(
      parsed.os_image_hash,
      "browser main runtime OS image hash",
    ),
    activation_signer_address: address(
      parsed.activation_signer_address,
      "browser activation signer",
    ),
    cvm_id: boundedIdentifier(
      parsed.cvm_id,
      "browser main runtime CVM ID",
    ),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "browser deployment intent",
    ),
    release_authority_sha256: sha256(
      parsed.release_authority_sha256,
      "browser release verification authority",
    ),
    ceremony_nonce: bytes32(
      parsed.ceremony_nonce,
      "browser ceremony nonce",
    ),
    measurement_policy_set_sha256: sha256(
      parsed.measurement_policy_set_sha256,
      "browser measurement-policy set",
    ),
    measurement_policy_sha256: sha256(
      parsed.measurement_policy_sha256,
      "browser compute-workload QVL measurement policy",
    ),
    main_runtime_evidence_sha256: sha256(
      parsed.main_runtime_evidence_sha256,
      "browser main-runtime evidence",
    ),
    chain_id: integer(parsed.chain_id, "browser chain ID", CHAIN_ID, CHAIN_ID),
    compute_vault_address: address(
      parsed.compute_vault_address,
      "browser ComputeCreditVault address",
    ),
    compute_vault_runtime_code_hash: bytes32(
      parsed.compute_vault_runtime_code_hash,
      "browser ComputeCreditVault runtime hash",
    ),
    fresh_contract_deployment_receipt_sha256: bytes32(
      parsed.fresh_contract_deployment_receipt_sha256,
      "browser fresh deployment receipt digest",
    ),
    max_verdict_age_seconds: integer(
      parsed.max_verdict_age_seconds,
      "browser maximum verdict age",
      1,
      300,
    ),
    revoked_quote_hashes: revoked,
  };
}

function browserBindingSha256(value) {
  return domainDigest(BROWSER_BINDING_DOMAIN, normalizeBrowserBinding(value));
}

function normalizeProjectedReleaseDescriptor(value, index) {
  const parsed = exactRecord(value, [
    "app_id", "compose_hash", "cvm_id", "cvm_key", "descriptor_sha256",
    "disk_size", "instance_type", "kms_id", "os_image_hash",
    "posture_observed_at", "posture_receipt_sha256",
  ], `projected release descriptor ${index}`);
  exactString(parsed.cvm_key, RELEASE_CVM_KEYS[index], `release descriptor ${index} key`);
  const postureObservedAt = parsed.posture_observed_at;
  secondTimestamp(postureObservedAt, `${parsed.cvm_key} posture observed_at`);
  if (typeof parsed.kms_id !== "string" || parsed.kms_id.length < 1
    || parsed.kms_id.length > 256 || typeof parsed.instance_type !== "string"
    || !/^[a-z][a-z0-9.-]{1,63}$/.test(parsed.instance_type)) {
    fail(`${parsed.cvm_key} resource posture is invalid`);
  }
  return {
    cvm_key: parsed.cvm_key,
    descriptor_sha256: sha256(parsed.descriptor_sha256, `${parsed.cvm_key} descriptor`),
    app_id: appId(parsed.app_id, `${parsed.cvm_key} app ID`),
    cvm_id: boundedIdentifier(parsed.cvm_id, `${parsed.cvm_key} CVM ID`),
    compose_hash: bareSha256(parsed.compose_hash, `${parsed.cvm_key} compose hash`),
    os_image_hash: bareSha256(parsed.os_image_hash, `${parsed.cvm_key} OS image hash`),
    posture_receipt_sha256: sha256(
      parsed.posture_receipt_sha256,
      `${parsed.cvm_key} posture receipt`,
    ),
    posture_observed_at: postureObservedAt,
    kms_id: parsed.kms_id,
    instance_type: parsed.instance_type,
    disk_size: integer(parsed.disk_size, `${parsed.cvm_key} disk size`, 20, 16_384),
  };
}

function normalizeProjectedLaunchCompletion(value, index) {
  const parsed = exactRecord(value, [
    "activation_evidence_lease_expires_at", "app_id",
    "attestation_evidence_sha256", "compose_hash", "cvm_id",
    "cvm_key", "descriptor_sha256", "disk_size", "instance_type", "kms_id",
    "os_image_hash", "posture_observed_at", "posture_receipt_sha256",
    "qvl_release_policy_sha256", "tee_identity",
  ], `projected historical L completion ${index}`);
  const descriptor = normalizeProjectedReleaseDescriptor({
    cvm_key: parsed.cvm_key,
    descriptor_sha256: parsed.descriptor_sha256,
    app_id: parsed.app_id,
    cvm_id: parsed.cvm_id,
    compose_hash: parsed.compose_hash,
    os_image_hash: parsed.os_image_hash,
    posture_receipt_sha256: parsed.posture_receipt_sha256,
    posture_observed_at: parsed.posture_observed_at,
    kms_id: parsed.kms_id,
    instance_type: parsed.instance_type,
    disk_size: parsed.disk_size,
  }, index);
  return {
    ...descriptor,
    tee_identity: address(parsed.tee_identity, `${parsed.cvm_key} TEE identity`),
    attestation_evidence_sha256: sha256(
      parsed.attestation_evidence_sha256,
      `${parsed.cvm_key} historical attestation evidence`,
    ),
    qvl_release_policy_sha256: sha256(
      parsed.qvl_release_policy_sha256,
      `${parsed.cvm_key} historical QVL release policy`,
    ),
    activation_evidence_lease_expires_at: integer(
      parsed.activation_evidence_lease_expires_at,
      `${parsed.cvm_key} historical activation-evidence lease expiry`,
      1,
    ),
  };
}

function normalizeActivationTarget(value) {
  const parsed = exactRecord(value, [
    "app_id", "compose_hash", "cvm_id", "descriptor_sha256", "domain",
    "os_image_hash",
  ], "historical activation plan target");
  exactString(parsed.domain, "main_runtime_cvm", "activation plan target domain");
  return {
    domain: parsed.domain,
    descriptor_sha256: sha256(parsed.descriptor_sha256, "activation target descriptor"),
    app_id: appId(parsed.app_id, "activation target app ID"),
    cvm_id: boundedIdentifier(parsed.cvm_id, "activation target CVM ID"),
    compose_hash: bareSha256(parsed.compose_hash, "activation target compose hash"),
    os_image_hash: bareSha256(parsed.os_image_hash, "activation target OS image hash"),
  };
}

export function normalizeHistoricalLiveActivationExpectedContext(value) {
  assertBoundedCanonicalGraph(value, "historical live activation expected context");
  const parsed = exactRecord(value, [
    "activation_evidence_lease_expires_at", "activation_plan_target",
    "allowed_environment_key_count",
    "allowed_environment_key_names_sha256", "batch_id",
    "ceremony_nonce", "compute_workload_qvl_measurement_policy_sha256",
    "cvm_launch_intent_sha256", "deployment_intent_sha256",
    "injected_environment_key_count", "injected_environment_key_names_sha256",
    "launch_completion_domains", "phala_recovery_directory_identity_anchor_sha256",
    "post_measurement_activation_plan_sha256",
    "pre_ceremony_runtime_authority_sha256",
    "qvl_measurement_policy_set_sha256", "release_authority_descriptors",
    "release_sha", "release_verification_authority_sha256",
    "runtime_commitment_key_names_sha256", "runtime_commitments_sha256",
    "schema", "seven_cvm_launch_completion_receipt_sha256",
    "seven_cvm_verified_evidence_set_sha256", "truth_status",
  ], "historical live activation expected context");
  exactString(
    parsed.schema,
    HISTORICAL_LIVE_ACTIVATION_EXPECTED_CONTEXT_SCHEMA,
    "historical live activation expected context schema",
  );
  exactString(
    parsed.truth_status,
    HISTORICAL_LIVE_ACTIVATION_EXPECTED_CONTEXT_TRUTH,
    "historical live activation expected context truth",
  );
  if (!Array.isArray(parsed.release_authority_descriptors)
    || parsed.release_authority_descriptors.length !== RELEASE_CVM_KEYS.length
    || !Array.isArray(parsed.launch_completion_domains)
    || parsed.launch_completion_domains.length !== RELEASE_CVM_KEYS.length) {
    fail("historical live activation context requires exact seven-CVM projections");
  }
  const releaseAuthorityDescriptors = parsed.release_authority_descriptors.map(
    normalizeProjectedReleaseDescriptor,
  );
  const launchCompletionDomains = parsed.launch_completion_domains.map(
    normalizeProjectedLaunchCompletion,
  );
  const activationEvidenceLeaseExpiresAt = integer(
    parsed.activation_evidence_lease_expires_at,
    "context activation-evidence lease expiry",
    1,
  );
  if (Math.min(...launchCompletionDomains.map(
    (entry) => entry.activation_evidence_lease_expires_at,
  )) !== activationEvidenceLeaseExpiresAt) {
    fail("context activation-evidence lease is not the exact seven-CVM minimum");
  }
  const comparableFields = [
    "cvm_key", "descriptor_sha256", "app_id", "cvm_id", "compose_hash",
    "os_image_hash", "posture_receipt_sha256", "posture_observed_at", "kms_id",
    "instance_type", "disk_size",
  ];
  for (let index = 0; index < RELEASE_CVM_KEYS.length; index += 1) {
    for (const field of comparableFields) {
      if (releaseAuthorityDescriptors[index][field]
          !== launchCompletionDomains[index][field]) {
        fail(`historical L ${RELEASE_CVM_KEYS[index]} ${field} differs from release authority`);
      }
    }
  }
  const target = normalizeActivationTarget(parsed.activation_plan_target);
  const main = releaseAuthorityDescriptors[0];
  for (const field of [
    "descriptor_sha256", "app_id", "cvm_id", "compose_hash", "os_image_hash",
  ]) {
    if (target[field] !== main[field]) {
      fail(`activation plan main target ${field} differs from release authority`);
    }
  }
  const allowedCount = integer(
    parsed.allowed_environment_key_count,
    "activation plan allowed environment key count",
    1,
  );
  const injectedCount = integer(
    parsed.injected_environment_key_count,
    "activation plan injected environment key count",
    1,
  );
  if (injectedCount > allowedCount) {
    fail("activation plan injected environment count exceeds allowlist");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: parsed.schema,
    truth_status: parsed.truth_status,
    release_sha: fixed(parsed.release_sha, SHA40, "context release SHA"),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "context deployment intent",
    ),
    cvm_launch_intent_sha256: sha256(
      parsed.cvm_launch_intent_sha256,
      "context CVM launch intent",
    ),
    release_verification_authority_sha256: sha256(
      parsed.release_verification_authority_sha256,
      "context release verification authority",
    ),
    seven_cvm_verified_evidence_set_sha256: sha256(
      parsed.seven_cvm_verified_evidence_set_sha256,
      "context seven-CVM verified evidence set",
    ),
    activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "context ceremony nonce"),
    qvl_measurement_policy_set_sha256: sha256(
      parsed.qvl_measurement_policy_set_sha256,
      "context QVL measurement-policy set",
    ),
    compute_workload_qvl_measurement_policy_sha256: sha256(
      parsed.compute_workload_qvl_measurement_policy_sha256,
      "context compute-workload QVL measurement policy",
    ),
    seven_cvm_launch_completion_receipt_sha256: sha256(
      parsed.seven_cvm_launch_completion_receipt_sha256,
      "context historical L digest",
    ),
    phala_recovery_directory_identity_anchor_sha256: sha256(
      parsed.phala_recovery_directory_identity_anchor_sha256,
      "context recovery-directory anchor",
    ),
    pre_ceremony_runtime_authority_sha256: sha256(
      parsed.pre_ceremony_runtime_authority_sha256,
      "context historical R digest",
    ),
    post_measurement_activation_plan_sha256: sha256(
      parsed.post_measurement_activation_plan_sha256,
      "context activation plan digest",
    ),
    batch_id: sha256(parsed.batch_id, "context launch batch"),
    activation_plan_target: target,
    runtime_commitments_sha256: sha256(
      parsed.runtime_commitments_sha256,
      "context runtime commitments",
    ),
    runtime_commitment_key_names_sha256: sha256(
      parsed.runtime_commitment_key_names_sha256,
      "context runtime commitment key names",
    ),
    allowed_environment_key_names_sha256: sha256(
      parsed.allowed_environment_key_names_sha256,
      "context allowed environment key names",
    ),
    allowed_environment_key_count: allowedCount,
    injected_environment_key_names_sha256: sha256(
      parsed.injected_environment_key_names_sha256,
      "context injected environment key names",
    ),
    injected_environment_key_count: injectedCount,
    release_authority_descriptors: releaseAuthorityDescriptors,
    launch_completion_domains: launchCompletionDomains,
  }, { label: "normalized historical live activation expected context" });
}

export function projectHistoricalLiveActivationExpectedContext({
  runtimeAuthority,
  runtimeAuthoritySha256,
  launchCompletionReceipt,
  launchCompletionReceiptSha256,
  releaseVerificationAuthority,
  releaseVerificationAuthoritySha256,
} = {}) {
  for (const [label, artifact] of [
    ["projected historical R", runtimeAuthority],
    ["projected historical L", launchCompletionReceipt],
    ["projected release verification authority", releaseVerificationAuthority],
  ]) {
    assertBoundedCanonicalGraph(artifact, label);
  }
  if (!isRecord(runtimeAuthority) || !isRecord(launchCompletionReceipt)
    || !isRecord(releaseVerificationAuthority)) {
    fail("historical live activation projector requires normalized L/R/release authority objects");
  }
  const plan = runtimeAuthority.post_measurement_activation_plan;
  const computeWorkloadQvlPolicy =
    releaseVerificationAuthority?.qvl_measurement_policies?.find(
      (entry) => entry.domain === "compute_workload_qvl_cvm",
    );
  if (!isRecord(plan) || !Array.isArray(releaseVerificationAuthority.descriptors)
    || !Array.isArray(launchCompletionReceipt.domains)
    || !isRecord(computeWorkloadQvlPolicy)
    || !same(plan.release_verification_authority, releaseVerificationAuthority)) {
    fail("historical live activation projector received inconsistent R/plan/authority values");
  }
  if (!SHA256.test(runtimeAuthoritySha256 || "")
    || runtimeAuthority.release_verification_authority_sha256
      !== releaseVerificationAuthoritySha256
    || plan.release_verification_authority_sha256
      !== releaseVerificationAuthoritySha256
    || runtimeAuthority.seven_cvm_launch_completion_receipt_sha256
      !== launchCompletionReceiptSha256
    || plan.seven_cvm_launch_completion_receipt_sha256
      !== launchCompletionReceiptSha256
    || launchCompletionReceipt.release_verification_authority_sha256
      !== releaseVerificationAuthoritySha256
    || launchCompletionReceipt.release_sha !== runtimeAuthority.release_sha
    || launchCompletionReceipt.deployment_intent_sha256
      !== runtimeAuthority.deployment_intent_sha256
    || launchCompletionReceipt.cvm_launch_intent_sha256
      !== runtimeAuthority.cvm_launch_intent_sha256
    || launchCompletionReceipt.batch_id !== plan.batch_id
    || launchCompletionReceipt.phala_recovery_directory_identity_anchor_sha256
      !== runtimeAuthority.phala_recovery_directory_identity_anchor_sha256
    || releaseVerificationAuthority.release_sha !== runtimeAuthority.release_sha
    || releaseVerificationAuthority.deployment_intent_sha256
      !== runtimeAuthority.deployment_intent_sha256) {
    fail("historical live activation projector digest lineage is inconsistent");
  }
  const releaseAuthorityDescriptors = releaseVerificationAuthority.descriptors.map(
    (entry) => ({
      cvm_key: entry.domain,
      descriptor_sha256: entry.descriptor_sha256,
      app_id: entry.app_id,
      cvm_id: entry.cvm_id,
      compose_hash: entry.compose_hash,
      os_image_hash: entry.os_image_hash,
      posture_receipt_sha256: entry.posture_receipt_sha256,
      posture_observed_at: entry.posture_observed_at,
      kms_id: entry.kms_id,
      instance_type: entry.instance_type,
      disk_size: entry.disk_size,
    }),
  );
  const launchCompletionDomains = launchCompletionReceipt.domains.map((entry) => ({
    cvm_key: entry.domain,
    descriptor_sha256: entry.descriptor_sha256,
    app_id: entry.app_id,
    cvm_id: entry.cvm_id,
    compose_hash: entry.committed_compose_hash,
    os_image_hash: entry.os_image_hash,
    posture_receipt_sha256:
      entry.production_posture_verification_receipt_sha256,
    posture_observed_at: entry.production_posture_verified_at,
    kms_id: entry.kms_id,
    instance_type: entry.instance_type,
    disk_size: entry.disk_size,
    tee_identity: entry.tee_identity,
    attestation_evidence_sha256: entry.machine_evidence_sha256,
    qvl_release_policy_sha256: entry.qvl_release_policy_sha256,
    activation_evidence_lease_expires_at:
      entry.activation_evidence_lease_expires_at,
  }));
  return normalizeHistoricalLiveActivationExpectedContext({
    schema: HISTORICAL_LIVE_ACTIVATION_EXPECTED_CONTEXT_SCHEMA,
    truth_status: HISTORICAL_LIVE_ACTIVATION_EXPECTED_CONTEXT_TRUTH,
    release_sha: runtimeAuthority.release_sha,
    deployment_intent_sha256: runtimeAuthority.deployment_intent_sha256,
    cvm_launch_intent_sha256: runtimeAuthority.cvm_launch_intent_sha256,
    release_verification_authority_sha256: releaseVerificationAuthoritySha256,
    seven_cvm_verified_evidence_set_sha256:
      plan.seven_cvm_verified_evidence_set_sha256,
    activation_evidence_lease_expires_at:
      plan.activation_evidence_lease_expires_at,
    ceremony_nonce: releaseVerificationAuthority.ceremony_nonce,
    qvl_measurement_policy_set_sha256:
      releaseVerificationAuthority.qvl_measurement_policy_set_sha256,
    compute_workload_qvl_measurement_policy_sha256:
      phalaQvlMeasurementPolicySha256(computeWorkloadQvlPolicy),
    seven_cvm_launch_completion_receipt_sha256: launchCompletionReceiptSha256,
    phala_recovery_directory_identity_anchor_sha256:
      runtimeAuthority.phala_recovery_directory_identity_anchor_sha256,
    pre_ceremony_runtime_authority_sha256: runtimeAuthoritySha256,
    post_measurement_activation_plan_sha256:
      runtimeAuthority.post_measurement_activation_plan_sha256,
    batch_id: plan.batch_id,
    activation_plan_target: plan.target,
    runtime_commitments_sha256:
      phalaPostMeasurementRuntimeCommitmentsSha256(plan.runtime_commitments),
    runtime_commitment_key_names_sha256:
      plan.runtime_commitment_key_names_sha256,
    allowed_environment_key_names_sha256:
      plan.allowed_environment_key_names_sha256,
    allowed_environment_key_count: plan.allowed_environment_key_count,
    injected_environment_key_names_sha256:
      plan.injected_environment_key_names_sha256,
    injected_environment_key_count: plan.injected_environment_key_names.length,
    release_authority_descriptors: releaseAuthorityDescriptors,
    launch_completion_domains: launchCompletionDomains,
  });
}

function assertReceiptMatchesHistoricalContext(receipt, context, {
  ceremonyAuthorizationSha256,
  ceremonyAuthorization,
}) {
  const target = context.activation_plan_target;
  if (receipt.release_sha !== context.release_sha
    || receipt.deployment_intent_sha256 !== context.deployment_intent_sha256
    || receipt.cvm_launch_intent_sha256 !== context.cvm_launch_intent_sha256
    || receipt.release_verification_authority_sha256
      !== context.release_verification_authority_sha256
    || receipt.seven_cvm_launch_completion_receipt_sha256
      !== context.seven_cvm_launch_completion_receipt_sha256
    || receipt.seven_cvm_verified_evidence_set_sha256
      !== context.seven_cvm_verified_evidence_set_sha256
    || receipt.initial_activation_evidence_lease_expires_at
      !== context.activation_evidence_lease_expires_at
    || receipt.phala_recovery_directory_identity_anchor_sha256
      !== context.phala_recovery_directory_identity_anchor_sha256
    || receipt.pre_ceremony_runtime_authority_sha256
      !== context.pre_ceremony_runtime_authority_sha256
    || receipt.post_measurement_activation_plan_sha256
      !== context.post_measurement_activation_plan_sha256
    || receipt.ceremony_authorization_sha256 !== ceremonyAuthorizationSha256
    || receipt.batch_id !== context.batch_id
    || receipt.target.descriptor_sha256 !== target.descriptor_sha256
    || receipt.target.app_id !== target.app_id
    || receipt.target.cvm_id !== target.cvm_id
    || receipt.target.compose_hash !== target.compose_hash
    || receipt.target.os_image_hash !== target.os_image_hash
    || receipt.runtime_commitments_sha256 !== context.runtime_commitments_sha256
    || receipt.runtime_commitment_key_names_sha256
      !== context.runtime_commitment_key_names_sha256
    || receipt.allowed_environment_key_names_sha256
      !== context.allowed_environment_key_names_sha256
    || receipt.allowed_environment_key_count
      !== context.allowed_environment_key_count
    || receipt.injected_environment_key_names_sha256
      !== context.injected_environment_key_names_sha256
    || receipt.injected_environment_key_count
      !== context.injected_environment_key_count) {
    fail("activation execution receipt differs from injected L/R/plan/release authority");
  }
  const bSignedAtMs = millisecondTimestamp(
    ceremonyAuthorization.review.signed_at,
    "B review signed_at",
  );
  const bExpiresAtMs = millisecondTimestamp(
    ceremonyAuthorization.review.expires_at,
    "B review expires_at",
  );
  if (secondTimestamp(receipt.patch.attempt_recorded_at, "receipt PATCH attempt")
      < bSignedAtMs
    || secondTimestamp(receipt.completed_at, "receipt completion") >= bExpiresAtMs) {
    fail("activation execution receipt is outside signed B execution time");
  }
}

function normalizeStageTwoBody(value, ceremonyAuthorization, context) {
  const parsed = exactRecord(value, [
    "ceremony_authorization_sha256", "ceremony_finalization",
    "ceremony_transactions", "common_finalized_state", "contract_state",
    "network", "post_ceremony_evidence", "release_sha", "schema", "status",
    "truth_status",
  ], "historical live activation body");
  exactString(parsed.schema, LIVE_ACTIVATION_AUTHORITY_SCHEMA, "live activation schema");
  exactString(parsed.status, LIVE_ACTIVATION_AUTHORITY_STATUS, "live activation status");
  exactString(
    parsed.truth_status,
    "separately_signed_post_ceremony_live_activation_authority",
    "live activation truth status",
  );
  if (parsed.release_sha !== ceremonyAuthorization.release_sha
    || parsed.release_sha !== context.release_sha) {
    fail("live activation release SHA drifted from B or historical context");
  }
  const ceremonyAuthorizationSha256 = domainDigest(
    CEREMONY_AUTHORIZATION_CORE_DOMAIN,
    ceremonyAuthorization,
  );
  requireEqual(
    parsed.ceremony_authorization_sha256,
    ceremonyAuthorizationSha256,
    "live activation B digest",
  );
  const finalization = exactRecord(parsed.ceremony_finalization, [
    "finalization_receipt_sha256", "frozen_final_ledger_bytes",
    "frozen_final_ledger_mode", "frozen_final_ledger_sha256",
    "immutable_deployment_manifest_sha256", "initialization_receipt_sha256",
    "ledger_path", "lock_protocol", "revision_chain_sha256", "revision_count",
  ], "historical ceremony finalization");
  const normalizedFinalization = {
    immutable_deployment_manifest_sha256: sha256(
      finalization.immutable_deployment_manifest_sha256,
      "immutable deployment manifest digest",
    ),
    initialization_receipt_sha256: sha256(
      finalization.initialization_receipt_sha256,
      "ceremony ledger initialization receipt digest",
    ),
    ledger_path: canonicalAbsolutePath(
      finalization.ledger_path,
      "final ceremony ledger path",
    ),
    frozen_final_ledger_sha256: sha256(
      finalization.frozen_final_ledger_sha256,
      "frozen final ceremony ledger digest",
    ),
    frozen_final_ledger_bytes: integer(
      finalization.frozen_final_ledger_bytes,
      "frozen final ceremony ledger bytes",
      2,
      MAX_BYTES,
    ),
    frozen_final_ledger_mode: integer(
      finalization.frozen_final_ledger_mode,
      "frozen final ceremony ledger mode",
      0o444,
      0o444,
    ),
    finalization_receipt_sha256: sha256(
      finalization.finalization_receipt_sha256,
      "ceremony ledger finalization receipt digest",
    ),
    revision_chain_sha256: sha256(
      finalization.revision_chain_sha256,
      "ceremony ledger revision chain digest",
    ),
    revision_count: integer(
      finalization.revision_count,
      "ceremony ledger revision count",
      RELEASE_CEREMONY_MUTATION_WRITERS.length,
      RELEASE_CEREMONY_MUTATION_WRITERS.length,
    ),
    lock_protocol: exactString(
      finalization.lock_protocol,
      RELEASE_CEREMONY_LOCK_PROTOCOL,
      "ceremony finalization lock protocol",
    ),
  };
  const bManifest = ceremonyAuthorization.deployment_authority
    .immutable_deployment_manifest;
  const bLedger = ceremonyAuthorization.ceremony_ledger_initialization;
  if (normalizedFinalization.immutable_deployment_manifest_sha256
      !== bManifest.sha256
    || normalizedFinalization.initialization_receipt_sha256
      !== bLedger.initialization_receipt_sha256
    || normalizedFinalization.ledger_path !== bLedger.ledger_path
    || normalizedFinalization.frozen_final_ledger_sha256
      === bLedger.ledger_initial_sha256) {
    fail("ceremony finalization does not continue the exact B ledger lineage");
  }
  const commonFinalizedState = normalizeCommonFinalizedState(
    parsed.common_finalized_state,
  );
  if (!Array.isArray(parsed.ceremony_transactions)
    || parsed.ceremony_transactions.length
      !== ceremonyAuthorization.ceremony_transaction_plan.transactions.length) {
    fail("live activation must include all six B transaction evidences");
  }
  const transactions = parsed.ceremony_transactions.map((entry, index) =>
    normalizeCeremonyTransactionEvidence(
      entry,
      index,
      ceremonyAuthorization.ceremony_transaction_plan,
      commonFinalizedState,
    ));
  const bSignedAtMs = millisecondTimestamp(
    ceremonyAuthorization.review.signed_at,
    "B review signed_at",
  );
  const bExpiresAtMs = millisecondTimestamp(
    ceremonyAuthorization.review.expires_at,
    "B review expires_at",
  );
  if (transactions.some((entry) => {
    const minedAtMs = entry.primary_rpc_block.block_timestamp * 1_000;
    return minedAtMs < bSignedAtMs || minedAtMs >= bExpiresAtMs;
  })) {
    fail("every ceremony transaction must be mined during signed B");
  }
  if (transactions.some((entry) => entry.primary_rpc_block.block_number
      > commonFinalizedState.primary_rpc_block.block_number)) {
    fail("common finalized block does not cover every ceremony receipt");
  }
  const contractState = normalizeContractState(parsed.contract_state, {
    expectedDeploymentIntentSha256:
      ceremonyAuthorization.deployment_authority.deployment_intent_sha256,
    expectedReviewerGenesisAcceptanceSha256:
      ceremonyAuthorization.deployment_authority
        .reviewer_authority_genesis_acceptance_sha256,
    commonFinalizedState,
  });
  const post = exactRecord(parsed.post_ceremony_evidence, [
    "compute_workload_activation_observation_sha256",
    "compute_workload_browser_binding", "cvm_measurements_sha256",
    "final_cvms", "frontend_build_candidate_receipt_sha256",
    "frontend_build_sha256", "frontend_release_env_sha256",
    "post_measurement_activation_execution_receipt",
    "post_measurement_activation_execution_receipt_sha256",
    "qvl_policy_bundle_sha256", "tdx_attestation_bundle_sha256",
  ], "historical post-ceremony evidence");
  let activationExecutionReceipt;
  try {
    activationExecutionReceipt =
      normalizePhalaPostMeasurementActivationExecutionReceipt(
        post.post_measurement_activation_execution_receipt,
      );
  } catch (error) {
    fail(`post-ceremony activation execution receipt is invalid: ${error.message}`);
  }
  const activationExecutionReceiptSha256 =
    phalaPostMeasurementActivationExecutionReceiptSha256(
      activationExecutionReceipt,
    );
  requireEqual(
    post.post_measurement_activation_execution_receipt_sha256,
    activationExecutionReceiptSha256,
    "carried activation execution receipt digest",
  );
  assertReceiptMatchesHistoricalContext(activationExecutionReceipt, context, {
    ceremonyAuthorizationSha256,
    ceremonyAuthorization,
  });
  const finalCvms = normalizeFinalCvms(post.final_cvms);
  for (let index = 0; index < finalCvms.length; index += 1) {
    const finalCvm = finalCvms[index];
    const launch = context.launch_completion_domains[index];
    if (finalCvm.cvm_key !== launch.cvm_key
      || finalCvm.app_id !== launch.app_id
      || finalCvm.cvm_id !== launch.cvm_id
      || finalCvm.compose_hash_sha256 !== `sha256:${launch.compose_hash}`
      || finalCvm.tee_identity !== launch.tee_identity) {
      fail(`signed C final ${finalCvm.cvm_key} differs from historical L descriptor`);
    }
    const expectedEvidence = finalCvm.cvm_key === "main_runtime_cvm"
      ? activationExecutionReceipt.post_restart_evidence
        .get_cvm_attestation_observation_sha256
      : launch.attestation_evidence_sha256;
    if (finalCvm.attestation_evidence_sha256 !== expectedEvidence) {
      fail(`signed C final ${finalCvm.cvm_key} attestation evidence drifted`);
    }
  }
  const browserBinding = normalizeBrowserBinding(
    post.compute_workload_browser_binding,
  );
  const main = context.release_authority_descriptors[0];
  const computeQvl = context.launch_completion_domains[
    RELEASE_CVM_KEYS.indexOf("compute_workload_qvl_cvm")
  ];
  const computeVault = contractState.contracts.find(
    (entry) => entry.contract_key === "compute_credit_vault",
  );
  if (browserBinding.app_id !== main.app_id
    || browserBinding.cvm_id !== main.cvm_id
    || browserBinding.compose_hash !== `0x${main.compose_hash}`
    || browserBinding.os_image_hash !== main.os_image_hash
    || browserBinding.main_runtime_evidence_sha256
      !== context.launch_completion_domains[0].attestation_evidence_sha256
    || browserBinding.qvl_verifier !== computeQvl.tee_identity
    || browserBinding.qvl_release_policy_hash
      !== `0x${computeQvl.qvl_release_policy_sha256.slice(7)}`
    || browserBinding.deployment_intent_sha256
      !== context.deployment_intent_sha256
    || browserBinding.release_authority_sha256
      !== context.release_verification_authority_sha256
    || browserBinding.ceremony_nonce !== context.ceremony_nonce
    || browserBinding.measurement_policy_set_sha256
      !== context.qvl_measurement_policy_set_sha256
    || browserBinding.measurement_policy_sha256
      !== context.compute_workload_qvl_measurement_policy_sha256
    || browserBinding.compute_vault_address !== computeVault.address
    || browserBinding.compute_vault_runtime_code_hash
      !== computeVault.runtime_code_hash
    || browserBinding.fresh_contract_deployment_receipt_sha256
      !== `0x${ceremonyAuthorization.deployment_authority
        .fresh_contract_deployment_receipt_sha256.slice(7)}`) {
    fail("signed C browser binding differs from L or finalized contract state");
  }
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    release_sha: parsed.release_sha,
    network: network(parsed.network, "live activation network"),
    ceremony_authorization_sha256: ceremonyAuthorizationSha256,
    ceremony_finalization: normalizedFinalization,
    ceremony_transactions: transactions,
    common_finalized_state: commonFinalizedState,
    contract_state: contractState,
    post_ceremony_evidence: {
      final_cvms: finalCvms,
      cvm_measurements_sha256: sha256(
        post.cvm_measurements_sha256,
        "CVM measurements digest",
      ),
      tdx_attestation_bundle_sha256: sha256(
        post.tdx_attestation_bundle_sha256,
        "TDX attestation bundle digest",
      ),
      qvl_policy_bundle_sha256: sha256(
        post.qvl_policy_bundle_sha256,
        "QVL policy bundle digest",
      ),
      post_measurement_activation_execution_receipt:
        activationExecutionReceipt,
      post_measurement_activation_execution_receipt_sha256:
        activationExecutionReceiptSha256,
      compute_workload_activation_observation_sha256: sha256(
        post.compute_workload_activation_observation_sha256,
        "compute-workload activation observation digest",
      ),
      compute_workload_browser_binding: browserBinding,
      frontend_release_env_sha256: sha256(
        post.frontend_release_env_sha256,
        "frontend release environment digest",
      ),
      frontend_build_candidate_receipt_sha256: sha256(
        post.frontend_build_candidate_receipt_sha256,
        "frontend build candidate receipt digest",
      ),
      frontend_build_sha256: sha256(
        post.frontend_build_sha256,
        "frontend build digest",
      ),
    },
  };
}

function commonStateDependencySha256(commonState) {
  return domainDigest("dnai-wikigen/common-finalized-state/v2\0", commonState);
}

function stageTwoDependencies(body) {
  const finalCvmStateSha256 = domainDigest(
    "dnai-wikigen/final-cvm-state/v1\0",
    body.post_ceremony_evidence.final_cvms,
  );
  const map = {
    ceremony_authorization: body.ceremony_authorization_sha256,
    immutable_deployment_manifest:
      body.ceremony_finalization.immutable_deployment_manifest_sha256,
    ceremony_ledger_initialization_receipt:
      body.ceremony_finalization.initialization_receipt_sha256,
    frozen_final_ceremony_ledger:
      body.ceremony_finalization.frozen_final_ledger_sha256,
    ceremony_ledger_finalization_receipt:
      body.ceremony_finalization.finalization_receipt_sha256,
    ceremony_ledger_revision_chain:
      body.ceremony_finalization.revision_chain_sha256,
    common_finalized_state: commonStateDependencySha256(body.common_finalized_state),
    contract_configuration_set: body.contract_state.configuration_set_sha256,
    challenge_genesis: body.contract_state.challenge_genesis_sha256,
    final_cvm_state: finalCvmStateSha256,
    cvm_measurements: body.post_ceremony_evidence.cvm_measurements_sha256,
    tdx_attestation_bundle:
      body.post_ceremony_evidence.tdx_attestation_bundle_sha256,
    qvl_policy_bundle: body.post_ceremony_evidence.qvl_policy_bundle_sha256,
    post_measurement_activation_execution_receipt:
      body.post_ceremony_evidence
        .post_measurement_activation_execution_receipt_sha256,
    compute_workload_activation_observation:
      body.post_ceremony_evidence.compute_workload_activation_observation_sha256,
    compute_workload_browser_binding: browserBindingSha256(
      body.post_ceremony_evidence.compute_workload_browser_binding,
    ),
    frontend_release_env:
      body.post_ceremony_evidence.frontend_release_env_sha256,
    frontend_build_candidate_receipt:
      body.post_ceremony_evidence.frontend_build_candidate_receipt_sha256,
    frontend_build: body.post_ceremony_evidence.frontend_build_sha256,
  };
  return STAGE_TWO_DEPENDENCY_KINDS.map((kind) => ({ kind, sha256: map[kind] }));
}

export function historicalLiveActivationReviewSubjectSha256(
  unsignedBody,
  {
    ceremonyAuthorization,
    ceremonyAuthorizationOptions,
    expectedContext,
  } = {},
) {
  const b = normalizeHistoricalCeremonyAuthorizationCore(
    ceremonyAuthorization,
    ceremonyAuthorizationOptions,
  );
  const context = normalizeHistoricalLiveActivationExpectedContext(expectedContext);
  return domainDigest(
    LIVE_ACTIVATION_REVIEW_SUBJECT_DOMAIN,
    normalizeStageTwoBody(unsignedBody, b, context),
  );
}

export function historicalLiveActivationReviewSigningPayload(
  unsignedBody,
  reviewMetadata,
  {
    ceremonyAuthorization,
    ceremonyAuthorizationOptions,
    expectedContext,
    reviewerAuthority,
    expectedSignatureVerifier,
  } = {},
) {
  const b = normalizeHistoricalCeremonyAuthorizationCore(
    ceremonyAuthorization,
    ceremonyAuthorizationOptions,
  );
  const context = normalizeHistoricalLiveActivationExpectedContext(expectedContext);
  const authority = normalizeHistoricalReviewerAuthority(reviewerAuthority);
  const body = normalizeStageTwoBody(unsignedBody, b, context);
  return normalizeHistoricalReviewSigningPayload({
    schema: RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA,
    stage: LIVE_ACTIVATION_AUTHORITY_STATUS,
    subject_kind: LIVE_ACTIVATION_REVIEW_SUBJECT_KIND,
    release_sha: body.release_sha,
    chain_id: CHAIN_ID,
    subject_sha256: domainDigest(LIVE_ACTIVATION_REVIEW_SUBJECT_DOMAIN, body),
    dependencies: stageTwoDependencies(body),
    reviewer_authority_genesis_sha256:
      authority.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      authority.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      authority.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      authority.reviewer_authority_current_status_sha256,
    approved_reviewer_hashes: authority.approved_reviewer_hashes,
    reviewer_root_hash: authority.reviewer_root_hash,
    reviewer_set_sha256: authority.reviewer_set_sha256,
    ...reviewMetadata,
    signature_scheme: RELEASE_AUTHORITY_SIGNATURE_SCHEME,
    signature_verifier: expectedSignatureVerifier,
  }, { expectedSignatureVerifier });
}

export function normalizeHistoricalLiveActivationAuthority(value, {
  ceremonyAuthorization,
  ceremonyAuthorizationOptions,
  expectedContext,
  reviewerAuthority,
  expectedSignatureVerifier,
  verifyReviewSignatures,
} = {}) {
  assertBoundedCanonicalGraph(value, "historical live activation authority");
  const b = normalizeHistoricalCeremonyAuthorizationCore(
    ceremonyAuthorization,
    ceremonyAuthorizationOptions,
  );
  const context = normalizeHistoricalLiveActivationExpectedContext(expectedContext);
  const authority = normalizeHistoricalReviewerAuthority(reviewerAuthority);
  if (b.release_sha !== context.release_sha
    || b.deployment_authority.deployment_intent_sha256
      !== context.deployment_intent_sha256
    || b.cvm_launch_intent_sha256 !== context.cvm_launch_intent_sha256
    || b.pre_ceremony_runtime_authority_sha256
      !== context.pre_ceremony_runtime_authority_sha256) {
    fail("historical C context differs from normalized B/R lineage");
  }
  const parsed = exactRecord(value, [
    "ceremony_authorization_sha256", "ceremony_finalization",
    "ceremony_transactions", "common_finalized_state", "contract_state",
    "network", "post_ceremony_evidence", "release_sha", "review", "schema",
    "status", "truth_status",
  ], "historical live activation authority");
  const body = normalizeStageTwoBody(
    Object.fromEntries(Object.entries(parsed).filter(([key]) => key !== "review")),
    b,
    context,
  );
  const review = normalizeCryptographicReview(parsed.review, {
    stage: LIVE_ACTIVATION_AUTHORITY_STATUS,
    subjectKind: LIVE_ACTIVATION_REVIEW_SUBJECT_KIND,
    subjectSha256: domainDigest(LIVE_ACTIVATION_REVIEW_SUBJECT_DOMAIN, body),
    releaseSha: body.release_sha,
    dependencies: stageTwoDependencies(body),
    reviewerAuthority: authority,
    expectedSignatureVerifier,
    verifyReviewSignatures,
  });
  const receipt = body.post_ceremony_evidence
    .post_measurement_activation_execution_receipt;
  const reviewSignedAtMs = millisecondTimestamp(
    review.signed_at,
    "C review signed_at",
  );
  if (reviewSignedAtMs < secondTimestamp(receipt.completed_at, "receipt completion")
    || reviewSignedAtMs >= receipt.terminal_evidence_lease_expires_at * 1_000) {
    fail("C review was not signed after receipt completion within terminal evidence lease");
  }
  return deepFreezeCanonicalPlainDataGraph(
    { ...body, review },
    { label: "normalized historical live activation authority" },
  );
}

export function historicalLiveActivationAuthoritySha256(value, options) {
  return domainDigest(
    LIVE_ACTIVATION_AUTHORITY_DOMAIN,
    normalizeHistoricalLiveActivationAuthority(value, options),
  );
}

export function normalizeHistoricalLiveActivationFrontendBinding(value) {
  assertBoundedCanonicalGraph(value, "historical live activation frontend binding");
  const parsed = exactRecord(value, [
    "ceremony_authorization_sha256", "chain_id", "challenge_genesis_sha256",
    "common_finalized_state_sha256", "contract_configuration_set_sha256",
    "compute_workload_activation_observation_sha256",
    "compute_workload_browser_binding", "contracts", "cvm_measurements_sha256",
    "deployment_intent_sha256", "execution_policy_anchor_commitment",
    "final_cvms", "frontend_build_candidate_receipt_sha256",
    "frontend_build_sha256", "frontend_release_env_sha256",
    "live_activation_authority_sha256", "qvl_policy_bundle_sha256",
    "release_sha", "reviewer_authority_genesis_acceptance_sha256",
    "runtime_authority_dependency_sha256", "schema",
    "tdx_attestation_bundle_sha256", "truth_status",
  ], "historical live activation frontend binding");
  exactString(
    parsed.schema,
    LIVE_ACTIVATION_FRONTEND_BINDING_SCHEMA,
    "live activation frontend binding schema",
  );
  exactString(
    parsed.truth_status,
    LIVE_ACTIVATION_FRONTEND_BINDING_TRUTH_STATUS,
    "live activation frontend binding truth status",
  );
  const deploymentIntentSha256 = sha256(
    parsed.deployment_intent_sha256,
    "frontend binding deployment intent digest",
  );
  const reviewerGenesisAcceptanceSha256 = sha256(
    parsed.reviewer_authority_genesis_acceptance_sha256,
    "frontend binding reviewer genesis acceptance digest",
  );
  const contracts = normalizeContractEntries(parsed.contracts);
  const challengeGenesisSha256 = sha256(
    parsed.challenge_genesis_sha256,
    "frontend binding challenge genesis digest",
  );
  const executionPolicyAnchorCommitment =
    normalizeExecutionPolicyAnchorCommitment(
      parsed.execution_policy_anchor_commitment,
      {
        contracts,
        deploymentIntentSha256,
        reviewerGenesisAcceptanceSha256,
      },
    );
  const configurationSetSha256 = domainDigest(
    "dnai-wikigen/live-contract-configuration-set/v2\0",
    contractConfigurationSetPayload({
      contracts,
      challengeGenesisSha256,
      deploymentIntentSha256,
      reviewerGenesisAcceptanceSha256,
      executionPolicyAnchorCommitment,
    }),
  );
  requireEqual(
    parsed.contract_configuration_set_sha256,
    configurationSetSha256,
    "frontend binding contract configuration digest",
  );
  return deepFreezeCanonicalPlainDataGraph({
    schema: parsed.schema,
    truth_status: parsed.truth_status,
    release_sha: fixed(parsed.release_sha, SHA40, "frontend binding release SHA"),
    chain_id: integer(parsed.chain_id, "frontend binding chain ID", CHAIN_ID, CHAIN_ID),
    live_activation_authority_sha256: sha256(
      parsed.live_activation_authority_sha256,
      "frontend binding live activation authority digest",
    ),
    deployment_intent_sha256: deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerGenesisAcceptanceSha256,
    ceremony_authorization_sha256: sha256(
      parsed.ceremony_authorization_sha256,
      "frontend binding B digest",
    ),
    runtime_authority_dependency_sha256: sha256(
      parsed.runtime_authority_dependency_sha256,
      "frontend binding R digest",
    ),
    frontend_build_candidate_receipt_sha256: sha256(
      parsed.frontend_build_candidate_receipt_sha256,
      "frontend binding D receipt digest",
    ),
    frontend_build_sha256: sha256(
      parsed.frontend_build_sha256,
      "frontend binding build digest",
    ),
    common_finalized_state_sha256: sha256(
      parsed.common_finalized_state_sha256,
      "frontend binding common finalized state digest",
    ),
    contract_configuration_set_sha256: configurationSetSha256,
    contracts,
    execution_policy_anchor_commitment: executionPolicyAnchorCommitment,
    challenge_genesis_sha256: challengeGenesisSha256,
    final_cvms: normalizeFinalCvms(parsed.final_cvms),
    cvm_measurements_sha256: sha256(
      parsed.cvm_measurements_sha256,
      "frontend binding CVM measurements digest",
    ),
    tdx_attestation_bundle_sha256: sha256(
      parsed.tdx_attestation_bundle_sha256,
      "frontend binding TDX attestation bundle digest",
    ),
    qvl_policy_bundle_sha256: sha256(
      parsed.qvl_policy_bundle_sha256,
      "frontend binding QVL policy bundle digest",
    ),
    compute_workload_activation_observation_sha256: sha256(
      parsed.compute_workload_activation_observation_sha256,
      "frontend binding workload observation digest",
    ),
    compute_workload_browser_binding: normalizeBrowserBinding(
      parsed.compute_workload_browser_binding,
    ),
    frontend_release_env_sha256: sha256(
      parsed.frontend_release_env_sha256,
      "frontend binding release environment digest",
    ),
  }, { label: "normalized historical live activation frontend binding" });
}

export function projectHistoricalLiveActivationFrontendBinding(value, options) {
  const liveActivation = normalizeHistoricalLiveActivationAuthority(value, options);
  const ceremonyAuthorization = normalizeHistoricalCeremonyAuthorizationCore(
    options?.ceremonyAuthorization,
    options?.ceremonyAuthorizationOptions,
  );
  const post = liveActivation.post_ceremony_evidence;
  return normalizeHistoricalLiveActivationFrontendBinding({
    schema: LIVE_ACTIVATION_FRONTEND_BINDING_SCHEMA,
    truth_status: LIVE_ACTIVATION_FRONTEND_BINDING_TRUTH_STATUS,
    release_sha: liveActivation.release_sha,
    chain_id: CHAIN_ID,
    live_activation_authority_sha256:
      historicalLiveActivationAuthoritySha256(value, options),
    deployment_intent_sha256:
      liveActivation.contract_state.deployment_intent_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      liveActivation.contract_state.reviewer_authority_genesis_acceptance_sha256,
    ceremony_authorization_sha256: liveActivation.ceremony_authorization_sha256,
    runtime_authority_dependency_sha256:
      ceremonyAuthorization.pre_ceremony_runtime_authority_sha256,
    frontend_build_candidate_receipt_sha256:
      post.frontend_build_candidate_receipt_sha256,
    frontend_build_sha256: post.frontend_build_sha256,
    common_finalized_state_sha256:
      commonStateDependencySha256(liveActivation.common_finalized_state),
    contract_configuration_set_sha256:
      liveActivation.contract_state.configuration_set_sha256,
    contracts: liveActivation.contract_state.contracts,
    execution_policy_anchor_commitment:
      liveActivation.contract_state.execution_policy_anchor_commitment,
    challenge_genesis_sha256:
      liveActivation.contract_state.challenge_genesis_sha256,
    final_cvms: post.final_cvms,
    cvm_measurements_sha256: post.cvm_measurements_sha256,
    tdx_attestation_bundle_sha256: post.tdx_attestation_bundle_sha256,
    qvl_policy_bundle_sha256: post.qvl_policy_bundle_sha256,
    compute_workload_activation_observation_sha256:
      post.compute_workload_activation_observation_sha256,
    compute_workload_browser_binding: post.compute_workload_browser_binding,
    frontend_release_env_sha256: post.frontend_release_env_sha256,
  });
}

export function historicalLiveActivationFrontendBindingSha256(value) {
  return domainDigest(
    LIVE_ACTIVATION_FRONTEND_BINDING_DOMAIN,
    normalizeHistoricalLiveActivationFrontendBinding(value),
  );
}
