import path from "node:path";
import { createHash } from "node:crypto";
import {
  CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS,
  FRESH_DEPLOYMENT_TRANSACTION_SPEC,
  freshContractDeploymentReceiptDigest,
  projectFreshContractDeploymentReceipt,
} from "./cvm-launch-intent-core.mjs";
import { FINAL_RELEASE_AUTHORITY_CORE_SCHEMA } from "./execution-policy-release-core.mjs";
import {
  DEPLOYMENT_INTENT_CORE_SCHEMA,
  TINKER_MAX_POLICY_UNITS_PER_OPERATION,
} from "./operator-policy-packet-core.mjs";
import {
  PHALA_RELEASE_MANIFEST_SIGSTORE_VERIFICATION_MISSING,
} from "./phala-production-execution-policy.mjs";

export {
  PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_DISABLED_CODE,
  PHALA_RELEASE_MANIFEST_SIGSTORE_VERIFICATION_MISSING,
} from "./phala-production-execution-policy.mjs";

export const PREFLIGHT_SCHEMA = "dnai.activation-preflight.v2";
export const SEMANTIC_VALIDATION_SCHEMA =
  "dnai.semantic-live-activation-validation.v3";
export const SEMANTIC_VALIDATION_STATUS =
  "live_activation_authority_validated";
export const SEMANTIC_VALIDATION_TRUTH_STATUS =
  "verified_signed_post_ceremony_C_revalidated_private_O_exact_env_D_and_dist_manifest_lineage";
export const LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA =
  "dnai.live-activation-authority-evidence.v1";
export const PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA =
  "dnai.pre-live-activation-authority-evidence.v1";
export const BASE_SEPOLIA_CHAIN_ID = "84532";
export const EXPECTED_IMAGE_PREFIX = "ghcr.io/therealwiki/dnai-wikigen/";
export const EXPECTED_GITHUB_REPOSITORY = "therealwiki/dnai-wikigen";
export const EXPECTED_GITHUB_WORKFLOW =
  "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml";
export const IMAGE_RELEASE_SCHEMA = "dnai.tee-image-release.v1";
export const CVM_TOPOLOGY_SCHEMA = "dnai.cvm-topology.v6";
export const RELEASE_MANIFEST_PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1";
export const EXPECTED_PLATFORM = "linux/amd64";
export const CANONICAL_SEVEN_CVM_AUTHORITY_VALIDATION_SOURCE =
  "shared_signed_c_dependency_validator";
export const CANONICAL_SEVEN_CVM_AUTHORITY_VALIDATION_STATUS =
  "canonical_seven_cvm_authority_validated";
export const CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_MODE =
  "fresh_release_ceremony";
export const CANONICAL_SEVEN_CVM_AUTHORITY_HISTORICAL_MODE =
  "historical_live_activation";
export const CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_TRUTH =
  "fresh_v3_release_lineage_descriptor_posture_policy_and_seven_machine_evidence_validated";
export const CANONICAL_SEVEN_CVM_AUTHORITY_HISTORICAL_TRUTH =
  "signed_c_b_r_l_o_d_and_historical_v3_transcript_dependency_chain_validated";

export const REQUIRED_TOOLS = Object.freeze([
  "git",
  "forge",
  "cast",
  "jq",
  "gh",
  "phala",
  "wrangler",
  "uv",
]);

export const REQUIRED_ROLE_KEYS = Object.freeze([
  "DEPLOYMENT_OPERATOR",
  "DILIGENCE_RESULT_VERIFIER",
  "COMPUTE_VAULT_DEVELOPER",
  "COMPUTE_VAULT_METERING_VERIFIER",
  "COMPUTE_VAULT_METERING_QVL_VERIFIER",
]);

const CONSTRUCTOR_STAGE_ROLE_KEYS = Object.freeze([
  "DEPLOYMENT_OPERATOR",
  "COMPUTE_VAULT_DEVELOPER",
]);

export const REQUIRED_PRODUCTION_SERVICES = Object.freeze([
  "neko",
  "oracle",
  "delegate",
  "diligence-policy-init",
  "arena-policy-init",
  "arena-worker",
  "anchor-writer-evidence",
  "deal-runtime",
  "compute-execution-worker",
]);

export const REQUIRED_QVL_SERVICES = Object.freeze(["policy-init", "qvl"]);
export const REQUIRED_METERING_SERVICES = Object.freeze([
  "policy-init",
  "state-init",
  "metering",
]);

export const REQUIRED_IMAGE_SUFFIXES = Object.freeze([
  "tinker-delegate",
  "tee-email-oracle",
  "neko-chrome",
  "attestation-qvl",
  "compute-metering",
]);

const EXPECTED_SERVICE_IMAGE_SUFFIX = Object.freeze({
  neko: "neko-chrome",
  oracle: "tee-email-oracle",
  "diligence-policy-init": "tinker-delegate",
  delegate: "tinker-delegate",
  "arena-policy-init": "tinker-delegate",
  "arena-worker": "tinker-delegate",
  "anchor-writer-evidence": "tinker-delegate",
  "deal-runtime": "tinker-delegate",
  "compute-execution-worker": "tinker-delegate",
});

export const QVL_DOMAINS = Object.freeze({
  diligence_qvl_cvm: Object.freeze({
    compose: "dnai-diligence-qvl.phala.yaml",
    context: "diligence",
  }),
  arena_qvl_cvm: Object.freeze({
    compose: "dnai-arena-qvl.phala.yaml",
    context: "arena",
  }),
  anchor_writer_qvl_cvm: Object.freeze({
    compose: "dnai-anchor-writer-qvl.phala.yaml",
    context: "execution_policy_anchor_writer",
  }),
  compute_workload_qvl_cvm: Object.freeze({
    compose: "dnai-compute-workload-qvl.phala.yaml",
    context: "compute_workload",
  }),
  compute_metering_qvl_cvm: Object.freeze({
    compose: "dnai-compute-metering-qvl.phala.yaml",
    context: "compute_metering",
  }),
});

export const CVM_TOPOLOGY_DOMAINS = Object.freeze([
  "main_runtime_cvm",
  "diligence_qvl_cvm",
  "arena_qvl_cvm",
  "anchor_writer_qvl_cvm",
  "compute_workload_qvl_cvm",
  "compute_metering_qvl_cvm",
  "independent_metering_cvm",
]);

export const CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS = Object.freeze([
  "transactionFound",
  "deployerMatches",
  "creationTransaction",
  "receiptFound",
  "receiptSuccessful",
  "contractAddressMatches",
  "deploymentBlockMatches",
  "deploymentBlockHashMatches",
  "runtimeCodeMatches",
]);

export const BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS = Object.freeze([
  "transactionFound",
  "senderMatches",
  "targetMatches",
  "nonceMatches",
  "valueZero",
  "inputMatches",
  "gasLimitValid",
  "transactionIndexValid",
  "receiptFound",
  "receiptSuccessful",
  "receiptSenderMatches",
  "receiptTargetMatches",
  "receiptContractAddressMatches",
  "receiptGasValid",
  "receiptTransactionIndexMatches",
  "blockMatches",
  "blockHashMatches",
  "secondaryTransactionFound",
  "secondarySenderMatches",
  "secondaryTargetMatches",
  "secondaryNonceMatches",
  "secondaryValueMatches",
  "secondaryInputMatches",
  "secondaryGasLimitMatches",
  "secondaryTransactionIndexMatches",
  "secondaryReceiptFound",
  "secondaryReceiptSuccessful",
  "secondaryReceiptSenderMatches",
  "secondaryReceiptTargetMatches",
  "secondaryReceiptContractAddressMatches",
  "secondaryReceiptGasMatches",
  "secondaryReceiptTransactionIndexMatches",
  "secondaryBlockMatches",
  "secondaryBlockHashMatches",
  "providerObservationsMatch",
]);

export const CONTRACT_STATELESS_POSTSTATE_EXCEPTION = "RoyaltyDistributor";
export const ACTIVATION_READINESS_SNAPSHOT_SCHEMA =
  "dnai.activation-readiness-snapshot.v3";
export const ACTIVATION_READINESS_SNAPSHOT_DOMAIN =
  "dnai-wikigen/activation-readiness-snapshot/v3\0";
export const ACTIVATION_READINESS_MAX_LIFETIME_MS = 120_000;
export const ACTIVATION_READINESS_TRUTH_STATUS =
  "read_only_readiness_evidence_not_standalone_authority_or_mutation";
export const ACTIVATION_READINESS_AUTHORIZED_ACTIONS = Object.freeze({
  cvm_launch: Object.freeze([
    "phala.nextAppIds.predict_exact_seven",
    "phala.provisionCvm.prepare_exact_seven_supporting_then_main",
    "phala.commitCvmProvision.bootstrap_exact_seven_supporting_then_main",
  ]),
  release_ceremony: Object.freeze([
    "contracts.configure.challenge_registry_genesis",
    "contracts.configure.compute_credit_vault",
    "contracts.configure.diligence_room",
    "contracts.configure.email_oracle_auth",
    "contracts.configure.execution_policy_anchor",
    "contracts.configure.tinker_account_encumbrance",
  ]),
  live_activation: Object.freeze(["cloudflare.deploy.pages"]),
});

export const ACTIVATION_READINESS_IMMEDIATE_RECHECK = Object.freeze({
  required: true,
  scope: "complete_chain_and_descriptor_bytes",
  before_first_mutation: true,
  repeat_before_each_mutation_after_expiry: true,
});

export const ACTIVATION_READINESS_EXECUTION_BOUNDARY = Object.freeze({
  cvm_launch: Object.freeze({
    availability: true,
    transport: "pinned_authenticated_phala_sdk_exact_origin_durable_replay",
    prepare_method: "provisionCvm_supporting_six_then_main",
    commit_method: "commitCvmProvision_supporting_six_then_main",
    phala_cli_role: "authentication_and_diagnostics_only_no_mutation_bypass",
    raw_private_key_allowed: false,
    reason_code: null,
    blocker_codes: Object.freeze([]),
  }),
  release_ceremony: Object.freeze({
    availability: true,
    transport: "foundry_encrypted_dev_keystore",
    prepare_method: "reviewed_release_helper",
    commit_method: "broadcast_after_complete_recheck",
    phala_cli_role: "not_applicable",
    raw_private_key_allowed: false,
    reason_code: null,
    blocker_codes: Object.freeze([]),
  }),
  live_activation: Object.freeze({
    availability: true,
    transport: "wrangler_cloudflare_pages",
    prepare_method: "pages_build_and_preflight",
    commit_method: "pages_deploy",
    phala_cli_role: "not_applicable",
    raw_private_key_allowed: false,
    reason_code: null,
    blocker_codes: Object.freeze([]),
  }),
});

const freezeAssertionMap = (value) => Object.freeze(Object.fromEntries(
  Object.entries(value).map(([name, assertions]) => [name, Object.freeze(assertions)]),
));

export const CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE = Object.freeze({
  fresh_fail_closed: freezeAssertionMap({
    ChallengeRegistry: [
      "owner_matches_operator",
      "pending_owner_unset",
      "registry_unpaused",
      "challenge_count_zero",
      "next_challenge_id_one",
    ],
    ComputeCreditVault: [
      "owner_matches_operator",
      "pending_owner_unset",
      "developer_matches_intent",
      "developer_fee_matches_intent_and_frozen",
      "paused",
      "metering_binding_unset",
      "metering_binding_not_frozen",
      "active_admission_counts_zero",
      "pending_admission_counts_zero",
      "asset_and_rate_policy_counts_zero",
      "admission_and_policy_additions_open",
    ],
    DiligenceRoom: [
      "developer_matches_operator",
      "constructor_bound_production_posture",
      "result_verifier_unset",
      "pending_result_verifier_unset",
      "result_verifier_not_frozen",
      "fee_policy_matches_intent_and_frozen",
      "approval_requirements_enforced_and_frozen",
      "attestation_binding_unset",
      "pending_attestation_binding_unset",
      "attestation_binding_not_frozen",
      "evaluator_policy_set_unset",
      "active_admission_counts_zero",
      "pending_admission_counts_zero",
      "admission_additions_open",
    ],
    EmailOracleAuth: [
      "owner_matches_operator",
      "constructor_bound_production_posture",
      "pending_owner_unset",
      "upgrade_delay_matches_intent",
      "deny_all",
      "release_not_ready",
      "active_admission_counts_zero",
      "pending_admission_counts_zero",
      "release_freezes_open",
    ],
    ExecutionPolicyAnchor: [
      "owner_matches_operator",
      "pending_owner_unset",
      "paused",
      "writer_unset",
      "pending_writer_unset",
      "writer_rotations_not_frozen",
      "global_sequence_zero",
      "global_head_zero",
    ],
    TinkerAccountEncumbrance: [
      "owner_matches_operator",
      "pending_owner_unset",
      "deployment_policy_matches_intent",
      "emergency_halted",
      "active_authority_empty",
      "pending_authority_empty",
      "release_authority_empty",
      "release_policy_not_frozen",
    ],
  }),
  final_active_frozen: freezeAssertionMap({
    ChallengeRegistry: [
      "owner_matches_final_authority",
      "pending_owner_unset",
      "registry_unpaused",
      "arena_registry_bindings_match_final_authority",
      "genesis_catalog_matches_final_authority",
      "active_challenge_count_at_least_one",
      "active_version_count_at_least_one",
      "active_challenges_unpaused",
      "active_challenge_configurations_frozen",
    ],
    ComputeCreditVault: [
      "owner_matches_final_authority",
      "pending_owner_unset",
      "developer_and_fee_match_final_authority",
      "metering_binding_matches_final_authority",
      "metering_binding_frozen",
      "admission_matches_final_authority",
      "rate_policies_match_final_authority",
      "assets_and_providers_match_final_authority",
      "all_additions_and_fee_frozen",
      "unpaused",
      "no_pending_authority",
    ],
    DiligenceRoom: [
      "developer_matches_final_authority",
      "constructor_bound_production_posture",
      "result_verifier_matches_final_authority",
      "result_verifier_frozen",
      "attestation_binding_matches_final_authority",
      "attestation_binding_frozen",
      "evaluator_policy_set_matches_final_authority",
      "release_admission_matches_final_authority",
      "release_admission_additions_frozen",
      "no_pending_authority",
    ],
    EmailOracleAuth: [
      "owner_matches_final_authority",
      "constructor_bound_production_posture",
      "pending_owner_unset",
      "release_tuple_matches_final_authority",
      "kms_tuple_matches_final_authority",
      "consumer_tuple_matches_final_authority",
      "release_freezes_closed",
      "release_ready",
      "no_pending_authority",
    ],
    ExecutionPolicyAnchor: [
      "owner_matches_final_authority",
      "pending_owner_unset",
      "writer_matches_final_authority",
      "writer_release_commitment_matches_final_authority",
      "writer_rotations_frozen",
      "unpaused",
      "no_pending_writer",
      "global_sequence_at_least_one",
      "global_head_matches_final_authority_digest",
    ],
    TinkerAccountEncumbrance: [
      "owner_matches_final_authority",
      "pending_owner_unset",
      "active_policy_matches_final_authority",
      "release_policy_matches_final_authority",
      "release_policy_frozen",
      "emergency_unhalted",
      "no_pending_authority",
      "per_operation_caps_enforced",
      "noncustodial",
    ],
  }),
});

const QVL_NUMERIC_ENVIRONMENT_KEYS = Object.freeze([
  "QVL_CHALLENGE_CAPACITY",
  "QVL_CHALLENGE_TTL_SECONDS",
  "QVL_MAX_CONCURRENCY",
  "QVL_RATE_CAPACITY",
  "QVL_RATE_REFILL_PER_SECOND",
  "QVL_REQUEST_BODY_TIMEOUT_SECONDS",
  "QVL_VERIFICATION_TIMEOUT_SECONDS",
]);

const METERING_NUMERIC_ENVIRONMENT_KEYS = Object.freeze([
  "METERING_MAX_CONCURRENCY",
  "METERING_RATE_CAPACITY",
  "METERING_RATE_REFILL_PER_SECOND",
  "METERING_REQUEST_BODY_TIMEOUT_SECONDS",
  "METERING_RPC_TIMEOUT_SECONDS",
]);

const REQUIRED_CONTRACT_INPUTS = Object.freeze([
  "BASE_SEPOLIA_RPC_URL",
  "BASE_SEPOLIA_SECONDARY_RPC_URL",
  "DEPLOYMENT_OPERATOR",
  "DILIGENCE_RESULT_VERIFIER",
  "COMPUTE_VAULT_DEVELOPER",
  "COMPUTE_VAULT_METERING_VERIFIER",
  "COMPUTE_VAULT_METERING_QVL_VERIFIER",
  "COMPUTE_VAULT_DEVELOPER_FEE_BPS",
  "TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT",
  "TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH",
  "TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI",
  "TINKER_ENCUMBRANCE_MAX_SPEND_WEI",
  "EMAIL_ORACLE_UPGRADE_DELAY",
  "RELEASE_SHA",
]);

export const REQUIRED_RUNTIME_CREDENTIALS = Object.freeze([
  ["credential.etherscan", "ETHERSCAN_API_KEY", "BaseScan verification credential"],
  [
    "credential.diligence_qvl",
    "TINKER_DILIGENCE_QVL_AUTH_TOKEN",
    "Diligence QVL bearer",
  ],
  ["credential.arena_qvl", "TINKER_ARENA_WORKER_QVL_AUTH_TOKEN", "Arena QVL bearer"],
  [
    "credential.anchor_writer_qvl",
    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN",
    "anchor-writer QVL bearer",
  ],
  [
    "credential.compute_workload_qvl",
    "TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN",
    "compute-workload QVL bearer",
  ],
  [
    "credential.compute_metering_qvl",
    "TINKER_COMPUTE_METERING_QVL_AUTH_TOKEN",
    "activation-verifier compute-metering QVL bearer",
  ],
  [
    "credential.metering_qvl",
    "METERING_QVL_AUTH_TOKEN",
    "metering-CVM compute-metering QVL bearer",
  ],
  ["credential.metering", "METERING_AUTH_TOKEN", "independent metering bearer"],
  [
    "credential.compute_metering",
    "TINKER_COMPUTE_METERING_AUTH_TOKEN",
    "Compute-to-metering bearer",
  ],
  ["credential.neko_user", "NEKO_PASSWORD", "Neko user credential"],
  ["credential.neko_admin", "NEKO_PASSWORD_ADMIN", "Neko administrator credential"],
]);

// The activation surface contains ten environment assignments but only eight
// independent secret domains. Two values intentionally cross a process
// boundary under different variable names: the activation verifier and meter
// are clients of the same compute-metering QVL, while the compute worker is a
// client of the independent meter. Every other domain must stay distinct.
export const INTERNAL_RUNTIME_CREDENTIAL_GROUPS = Object.freeze([
  Object.freeze(["TINKER_DILIGENCE_QVL_AUTH_TOKEN"]),
  Object.freeze(["TINKER_ARENA_WORKER_QVL_AUTH_TOKEN"]),
  Object.freeze(["TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN"]),
  Object.freeze(["TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN"]),
  Object.freeze([
    "TINKER_COMPUTE_METERING_QVL_AUTH_TOKEN",
    "METERING_QVL_AUTH_TOKEN",
  ]),
  Object.freeze([
    "METERING_AUTH_TOKEN",
    "TINKER_COMPUTE_METERING_AUTH_TOKEN",
  ]),
  Object.freeze(["NEKO_PASSWORD"]),
  Object.freeze(["NEKO_PASSWORD_ADMIN"]),
]);

const INTERNAL_RUNTIME_CREDENTIAL_KEYS = Object.freeze(
  INTERNAL_RUNTIME_CREDENTIAL_GROUPS.flat(),
);
const INTERNAL_RUNTIME_CREDENTIAL_KEY_SET = new Set(INTERNAL_RUNTIME_CREDENTIAL_KEYS);
const INTERNAL_RUNTIME_CREDENTIAL_PATTERN = /^[\x21-\x7e]{32,4096}$/;

const SECRET_NAME_PATTERN =
  /(?:KEY|TOKEN|PASSWORD|SECRET|AUTH|CREDENTIAL|RPC_URL|BASE_URL|PRIVATE)/i;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const IMAGE_PATTERN =
  /^ghcr\.io\/therealwiki\/dnai-wikigen\/[a-z0-9][a-z0-9._-]*@sha256:[0-9a-f]{64}$/;

function stripInlineComment(value) {
  let single = false;
  let double = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "'" && !double) single = !single;
    if (character === '"' && !single) double = !double;
    if (character === "#" && !single && !double) {
      const previous = index === 0 ? " " : value[index - 1];
      if (/\s/.test(previous)) return value.slice(0, index).trimEnd();
    }
  }
  return value;
}

function unquote(value) {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
    || (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

export function parseEnvText(text) {
  const values = {};
  for (const rawLine of String(text).split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const line = trimmed.startsWith("export ") ? trimmed.slice(7).trim() : trimmed;
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    values[key] = unquote(stripInlineComment(line.slice(separator + 1)));
  }
  return values;
}

export function clean(value) {
  const normalized = String(value ?? "").trim();
  return normalized === "undefined" || normalized === "null" ? "" : normalized;
}

export function validInternalRuntimeCredential(value) {
  const candidate = String(value ?? "");
  return INTERNAL_RUNTIME_CREDENTIAL_PATTERN.test(candidate)
    && Buffer.byteLength(candidate, "utf8") === candidate.length;
}

function canonicalJson(value) {
  const normalize = (item) => {
    if (Array.isArray(item)) return item.map(normalize);
    if (item && typeof item === "object") {
      return Object.fromEntries(
        Object.keys(item).sort().map((key) => [key, normalize(item[key])]),
      );
    }
    return item;
  };
  return JSON.stringify(normalize(value));
}

function isNonzeroAddress(value) {
  const normalized = clean(value).toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(normalized) && normalized !== ZERO_ADDRESS;
}

function isNonzeroBytes32(value) {
  const normalized = clean(value).toLowerCase();
  return /^0x[0-9a-f]{64}$/.test(normalized) && normalized !== ZERO_BYTES32;
}

function isNonzeroSha256(value) {
  const normalized = clean(value);
  return /^sha256:[0-9a-f]{64}$/.test(normalized)
    && normalized !== `sha256:${"0".repeat(64)}`;
}

function isUnsignedInteger(value) {
  return /^[0-9]+$/.test(clean(value));
}

function check(id, status, message, action = "") {
  if (!["pass", "warn", "fail"].includes(status)) {
    throw new Error(`invalid preflight status for ${id}`);
  }
  return {
    id: String(id).slice(0, 96),
    status,
    message: String(message).replace(/[\r\n]+/g, " ").slice(0, 240),
    ...(action
      ? { action: String(action).replace(/[\r\n]+/g, " ").slice(0, 240) }
      : {}),
  };
}

function validateContractInput(name, value) {
  if (!clean(value)) return false;
  if (["BASE_SEPOLIA_RPC_URL", "BASE_SEPOLIA_SECONDARY_RPC_URL"].includes(name)) {
    try {
      const endpoint = new URL(clean(value));
      return endpoint.protocol === "https:"
        && Boolean(endpoint.hostname)
        && !endpoint.username
        && !endpoint.password
        && !endpoint.hash
        && Buffer.byteLength(endpoint.href, "utf8") <= 4_096;
    } catch {
      return false;
    }
  }
  if (REQUIRED_ROLE_KEYS.includes(name)) return isNonzeroAddress(value);
  if ([
    "TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT",
    "TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH",
  ].includes(name)) return isNonzeroBytes32(value);
  if ([
    "COMPUTE_VAULT_DEVELOPER_FEE_BPS",
    "EMAIL_ORACLE_UPGRADE_DELAY",
  ].includes(name)) return isUnsignedInteger(value);
  if ([
    "TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI",
    "TINKER_ENCUMBRANCE_MAX_SPEND_WEI",
  ].includes(name)) {
    return isUnsignedInteger(value)
      && BigInt(clean(value)) > 0n
      && BigInt(clean(value)) <= TINKER_MAX_POLICY_UNITS_PER_OPERATION;
  }
  if (name === "RELEASE_SHA") return /^[0-9a-fA-F]{40}$/.test(clean(value));
  return true;
}

export function inspectCompose(composeText) {
  const invalid = { valid: false, services: {}, document: null };
  const text = String(composeText ?? "");
  const lines = text.split("\n");
  if (
    lines[0] !== "# Generated by tinker-release-composes. Do not edit by hand."
    || !/^# Input image manifest sha256: [0-9a-f]{64}$/.test(lines[1] || "")
    || lines[2]
      !== "# Status: rendered_not_deployed; deployment and TDX verification are separate gates."
    || !text.endsWith("\n")
  ) return invalid;
  const body = lines.slice(3).join("\n");
  let document;
  try {
    document = JSON.parse(body);
  } catch {
    return invalid;
  }
  // The renderer emits recursively key-sorted canonical JSON, which is also a
  // strict YAML 1.2/Compose document. Byte equality rejects duplicate keys,
  // aliases, merge semantics, alternate scalar spellings, and parser drift.
  if (`${JSON.stringify(document, null, 2)}\n` !== body) return invalid;
  if (
    !document
    || typeof document !== "object"
    || Array.isArray(document)
    || !document.services
    || typeof document.services !== "object"
    || Array.isArray(document.services)
  ) return invalid;
  const services = {};
  for (const [name, service] of Object.entries(document.services)) {
    if (!/^[A-Za-z0-9._-]+$/.test(name) || !service || typeof service !== "object") {
      return invalid;
    }
    services[name] = {
      ...service,
      image: clean(service.image),
      platform: clean(service.platform),
      raw: JSON.stringify(service),
    };
  }
  return { valid: true, services, document };
}

export function collectDigestImages(value, result = new Set()) {
  if (typeof value === "string") {
    if (/^ghcr\.io\/[^\s@]+@sha256:[0-9a-fA-F]{64}$/.test(value)) {
      result.add(value.toLowerCase());
    }
    return result;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectDigestImages(item, result);
    return result;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) collectDigestImages(item, result);
  }
  return result;
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

const ACTIVATION_READINESS_RPC_DOMAIN =
  "dnai-wikigen/activation-readiness-rpc-endpoint/v1\0";
const ACTIVATION_READINESS_RPC_ORIGIN_DOMAIN =
  "dnai-wikigen/activation-readiness-rpc-origin/v1\0";
const ACTIVATION_READINESS_PROVENANCE_DOMAIN =
  "dnai-wikigen/activation-readiness-immutable-provenance/v1\0";
const ACTIVATION_READINESS_BROADCAST_PROVENANCE_DOMAIN =
  "dnai-wikigen/activation-readiness-broadcast-provenance/v2\0";
const ACTIVATION_READINESS_POSTSTATES_DOMAIN =
  "dnai-wikigen/activation-readiness-poststates/v1\0";

function domainSeparatedSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(Buffer.from(domain, "utf8"))
    .update(Buffer.from(value, "utf8"))
    .digest("hex")}`;
}

function normalizedReadinessProvenance(value) {
  if (!Array.isArray(value)
    || value.length !== CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.length) {
    throw new Error("readiness immutable provenance must contain exactly seven contracts");
  }
  return value.map((entry, index) => {
    if (!exactObject(entry, ["name", ...CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS])
      || entry.name !== CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS[index].name
      || !CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS.every((key) => entry[key] === true)) {
      throw new Error("readiness immutable provenance is incomplete or out of order");
    }
    return {
      name: entry.name,
      ...Object.fromEntries(
        CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS.map((key) => [key, true]),
      ),
    };
  });
}

function normalizedReadinessBroadcastProvenance(value) {
  if (!Array.isArray(value)
    || value.length !== FRESH_DEPLOYMENT_TRANSACTION_SPEC.length) {
    throw new Error("readiness broadcast provenance must contain exactly 13 transactions");
  }
  return value.map((entry, index) => {
    const expected = FRESH_DEPLOYMENT_TRANSACTION_SPEC[index];
    if (!exactObject(entry, [
      "sequence",
      "contractKey",
      "transactionType",
      ...BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS,
    ])
      || entry.sequence !== index
      || entry.contractKey !== expected.contract_key
      || entry.transactionType !== expected.transaction_type
      || !BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS.every(
        (key) => entry[key] === true,
      )) {
      throw new Error("readiness broadcast provenance is incomplete or out of order");
    }
    return {
      sequence: index,
      contractKey: expected.contract_key,
      transactionType: expected.transaction_type,
      ...Object.fromEntries(
        BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS.map((key) => [key, true]),
      ),
    };
  });
}

function normalizedReadinessPoststates(value, mode) {
  const expectedEntries = Object.entries(CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE[mode] || {});
  if (!Array.isArray(value) || value.length !== 6 || expectedEntries.length !== 6) {
    throw new Error("readiness poststates must contain exactly six stateful contracts");
  }
  return value.map((entry, index) => {
    const [expectedName, expectedAssertions] = expectedEntries[index];
    if (!exactObject(entry, ["name", "valid", "assertions"])
      || entry.name !== expectedName
      || entry.valid !== true
      || !Array.isArray(entry.assertions)
      || entry.assertions.length !== expectedAssertions.length
      || !entry.assertions.every((assertion, assertionIndex) => (
        assertion === expectedAssertions[assertionIndex]
      ))) {
      throw new Error("readiness poststate assertions are incomplete or out of order");
    }
    return { name: expectedName, valid: true, assertions: [...expectedAssertions] };
  });
}

function normalizedUtcSecond(value, label) {
  if (typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isSafeInteger(milliseconds)
    || new Date(milliseconds).toISOString() !== value.replace(/Z$/, ".000Z")) {
    throw new Error(`${label} is not a real canonical UTC second`);
  }
  return { value, milliseconds };
}

export function activationReadinessRpcEndpointDigest(endpoint) {
  const value = String(endpoint ?? "").trim();
  if (!value || Buffer.byteLength(value, "utf8") > 4_096) {
    throw new Error("readiness RPC endpoint is missing or overlong");
  }
  return domainSeparatedSha256(ACTIVATION_READINESS_RPC_DOMAIN, value);
}

export function activationReadinessRpcOriginDigest(origin) {
  const value = String(origin ?? "").trim().toLowerCase();
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("readiness RPC origin is invalid");
  }
  if (value.length > 4_096
    || parsed.protocol !== "https:"
    || parsed.origin.toLowerCase() !== value
    || parsed.username
    || parsed.password
    || parsed.pathname !== "/"
    || parsed.search
    || parsed.hash) {
    throw new Error("readiness RPC origin must be an exact credential-free HTTPS origin");
  }
  return domainSeparatedSha256(ACTIVATION_READINESS_RPC_ORIGIN_DOMAIN, value);
}

export function activationReadinessImmutableProvenanceDigest(value) {
  return domainSeparatedSha256(
    ACTIVATION_READINESS_PROVENANCE_DOMAIN,
    canonicalJson(normalizedReadinessProvenance(value)),
  );
}

export function activationReadinessBroadcastProvenanceDigest(value) {
  return domainSeparatedSha256(
    ACTIVATION_READINESS_BROADCAST_PROVENANCE_DOMAIN,
    canonicalJson(normalizedReadinessBroadcastProvenance(value)),
  );
}

export function activationReadinessPoststatesDigest(value, mode) {
  return domainSeparatedSha256(
    ACTIVATION_READINESS_POSTSTATES_DOMAIN,
    canonicalJson({ mode, poststates: normalizedReadinessPoststates(value, mode) }),
  );
}

export function normalizeActivationReadinessSnapshot(value) {
  if (!exactObject(value, [
    "schema",
    "truth_status",
    "stage",
    "release_sha",
    "chain_id",
    "rpc_endpoint_sha256",
    "secondary_rpc_endpoint_sha256",
    "rpc_origin_sha256",
    "secondary_rpc_origin_sha256",
    "dual_rpc_reconstruction_agreement",
    "dual_rpc_broadcast_transaction_agreement",
    "dual_rpc_poststate_agreement",
    "deployment_intent_sha256",
    "contract_deployment_receipt_sha256",
    "cvm_launch_intent_sha256",
    "final_authority_sha256",
    "snapshot_block_number",
    "snapshot_block_hash",
    "snapshot_finality",
    "finalized_recheck_block_number",
    "finalized_recheck_block_hash",
    "immutable_provenance_contract_count",
    "immutable_provenance_sha256",
    "broadcast_transaction_count",
    "broadcast_transactions_sha256",
    "broadcast_transaction_provenance_sha256",
    "primary_broadcast_transaction_observations_sha256",
    "secondary_broadcast_transaction_observations_sha256",
    "independent_reconstruction_sha256",
    "poststate_mode",
    "poststate_contract_count",
    "poststates_sha256",
    "primary_poststate_observations_sha256",
    "secondary_poststate_observations_sha256",
    "stateless_poststate_exception",
    "descriptor_raw_bytes_sha256_by_domain",
    "checked_at",
    "expires_at",
    "authorized_next_actions",
    "immediate_recheck",
    "execution_boundary",
    "read_only",
    "remote_state_mutated",
    "raw_secret_egress",
  ])) {
    throw new Error("activation readiness snapshot fields are not exact");
  }
  const stage = value.stage;
  const actions = ACTIVATION_READINESS_AUTHORIZED_ACTIONS[stage];
  const expectedPoststateMode = stage === "live_activation"
    ? "final_active_frozen"
    : "fresh_fail_closed";
  if (value.schema !== ACTIVATION_READINESS_SNAPSHOT_SCHEMA
    || value.truth_status !== ACTIVATION_READINESS_TRUTH_STATUS
    || !actions
    || value.chain_id !== Number(BASE_SEPOLIA_CHAIN_ID)
    || !/^[0-9a-f]{40}$/.test(value.release_sha)
    || !isNonzeroSha256(value.rpc_endpoint_sha256)
    || !isNonzeroSha256(value.secondary_rpc_endpoint_sha256)
    || value.secondary_rpc_endpoint_sha256 === value.rpc_endpoint_sha256
    || !isNonzeroSha256(value.rpc_origin_sha256)
    || !isNonzeroSha256(value.secondary_rpc_origin_sha256)
    || value.secondary_rpc_origin_sha256 === value.rpc_origin_sha256
    || value.dual_rpc_reconstruction_agreement !== true
    || value.dual_rpc_broadcast_transaction_agreement !== true
    || value.dual_rpc_poststate_agreement !== true
    || !isNonzeroSha256(value.deployment_intent_sha256)
    || !isNonzeroSha256(value.contract_deployment_receipt_sha256)
    || !isNonzeroSha256(value.cvm_launch_intent_sha256)
    || (stage === "cvm_launch"
      ? value.final_authority_sha256 !== null
      : !isNonzeroSha256(value.final_authority_sha256))
    || !Number.isSafeInteger(value.snapshot_block_number)
    || value.snapshot_block_number < 1
    || !isNonzeroBytes32(value.snapshot_block_hash)
    || value.snapshot_block_hash !== clean(value.snapshot_block_hash).toLowerCase()
    || value.snapshot_finality !== "rpc_finalized"
    || !Number.isSafeInteger(value.finalized_recheck_block_number)
    || value.finalized_recheck_block_number < value.snapshot_block_number
    || !isNonzeroBytes32(value.finalized_recheck_block_hash)
    || value.finalized_recheck_block_hash
      !== clean(value.finalized_recheck_block_hash).toLowerCase()
    || value.immutable_provenance_contract_count
      !== CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.length
    || !isNonzeroSha256(value.immutable_provenance_sha256)
    || value.broadcast_transaction_count !== FRESH_DEPLOYMENT_TRANSACTION_SPEC.length
    || !isNonzeroSha256(value.broadcast_transactions_sha256)
    || !isNonzeroSha256(value.broadcast_transaction_provenance_sha256)
    || !isNonzeroSha256(value.primary_broadcast_transaction_observations_sha256)
    || !isNonzeroSha256(value.secondary_broadcast_transaction_observations_sha256)
    || value.primary_broadcast_transaction_observations_sha256
      !== value.secondary_broadcast_transaction_observations_sha256
    || !isNonzeroSha256(value.independent_reconstruction_sha256)
    || value.poststate_mode !== expectedPoststateMode
    || value.poststate_contract_count !== 6
    || !isNonzeroSha256(value.poststates_sha256)
    || !isNonzeroSha256(value.primary_poststate_observations_sha256)
    || !isNonzeroSha256(value.secondary_poststate_observations_sha256)
    || value.primary_poststate_observations_sha256
      !== value.secondary_poststate_observations_sha256
    || value.stateless_poststate_exception !== CONTRACT_STATELESS_POSTSTATE_EXCEPTION
    || value.read_only !== true
    || value.remote_state_mutated !== false
    || value.raw_secret_egress !== false) {
    throw new Error("activation readiness snapshot semantics are invalid");
  }
  if (!exactObject(
    value.descriptor_raw_bytes_sha256_by_domain,
    CVM_TOPOLOGY_DOMAINS,
  ) || !CVM_TOPOLOGY_DOMAINS.every((domain) => (
    isNonzeroSha256(value.descriptor_raw_bytes_sha256_by_domain[domain])
  ))) {
    throw new Error("activation readiness descriptor hashes are not exact");
  }
  if (!Array.isArray(value.authorized_next_actions)
    || value.authorized_next_actions.length !== actions.length
    || !value.authorized_next_actions.every((action, index) => action === actions[index])) {
    throw new Error("activation readiness actions do not match the stage");
  }
  if (!exactObject(value.immediate_recheck, [
    "required",
    "scope",
    "before_first_mutation",
    "repeat_before_each_mutation_after_expiry",
  ]) || Object.entries(ACTIVATION_READINESS_IMMEDIATE_RECHECK).some(
    ([key, expected]) => value.immediate_recheck[key] !== expected,
  )) {
    throw new Error("activation readiness immediate recheck policy is invalid");
  }
  const executionBoundary = ACTIVATION_READINESS_EXECUTION_BOUNDARY[stage];
  if (!exactObject(value.execution_boundary, [
    "availability",
    "transport",
    "prepare_method",
    "commit_method",
    "phala_cli_role",
    "raw_private_key_allowed",
    "reason_code",
    "blocker_codes",
  ]) || canonicalJson(value.execution_boundary) !== canonicalJson(executionBoundary)) {
    throw new Error("activation readiness execution boundary is invalid");
  }
  const checked = normalizedUtcSecond(value.checked_at, "checked_at");
  const expires = normalizedUtcSecond(value.expires_at, "expires_at");
  if (expires.milliseconds <= checked.milliseconds
    || expires.milliseconds - checked.milliseconds > ACTIVATION_READINESS_MAX_LIFETIME_MS) {
    throw new Error("activation readiness lifetime is invalid");
  }
  return {
    schema: ACTIVATION_READINESS_SNAPSHOT_SCHEMA,
    truth_status: ACTIVATION_READINESS_TRUTH_STATUS,
    stage,
    release_sha: value.release_sha,
    chain_id: Number(BASE_SEPOLIA_CHAIN_ID),
    rpc_endpoint_sha256: value.rpc_endpoint_sha256,
    secondary_rpc_endpoint_sha256: value.secondary_rpc_endpoint_sha256,
    rpc_origin_sha256: value.rpc_origin_sha256,
    secondary_rpc_origin_sha256: value.secondary_rpc_origin_sha256,
    dual_rpc_reconstruction_agreement: true,
    dual_rpc_broadcast_transaction_agreement: true,
    dual_rpc_poststate_agreement: true,
    deployment_intent_sha256: value.deployment_intent_sha256,
    contract_deployment_receipt_sha256: value.contract_deployment_receipt_sha256,
    cvm_launch_intent_sha256: value.cvm_launch_intent_sha256,
    final_authority_sha256: value.final_authority_sha256,
    snapshot_block_number: value.snapshot_block_number,
    snapshot_block_hash: value.snapshot_block_hash,
    snapshot_finality: "rpc_finalized",
    finalized_recheck_block_number: value.finalized_recheck_block_number,
    finalized_recheck_block_hash: value.finalized_recheck_block_hash,
    immutable_provenance_contract_count: CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.length,
    immutable_provenance_sha256: value.immutable_provenance_sha256,
    broadcast_transaction_count: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
    broadcast_transactions_sha256: value.broadcast_transactions_sha256,
    broadcast_transaction_provenance_sha256:
      value.broadcast_transaction_provenance_sha256,
    primary_broadcast_transaction_observations_sha256:
      value.primary_broadcast_transaction_observations_sha256,
    secondary_broadcast_transaction_observations_sha256:
      value.secondary_broadcast_transaction_observations_sha256,
    independent_reconstruction_sha256: value.independent_reconstruction_sha256,
    poststate_mode: expectedPoststateMode,
    poststate_contract_count: 6,
    poststates_sha256: value.poststates_sha256,
    primary_poststate_observations_sha256:
      value.primary_poststate_observations_sha256,
    secondary_poststate_observations_sha256:
      value.secondary_poststate_observations_sha256,
    stateless_poststate_exception: CONTRACT_STATELESS_POSTSTATE_EXCEPTION,
    descriptor_raw_bytes_sha256_by_domain: Object.fromEntries(
      CVM_TOPOLOGY_DOMAINS.map((domain) => [
        domain,
        value.descriptor_raw_bytes_sha256_by_domain[domain],
      ]),
    ),
    checked_at: checked.value,
    expires_at: expires.value,
    authorized_next_actions: [...actions],
    immediate_recheck: { ...ACTIVATION_READINESS_IMMEDIATE_RECHECK },
    execution_boundary: {
      ...executionBoundary,
      blocker_codes: [...executionBoundary.blocker_codes],
    },
    read_only: true,
    remote_state_mutated: false,
    raw_secret_egress: false,
  };
}

export function activationReadinessSnapshotDigest(value) {
  const normalized = normalizeActivationReadinessSnapshot(value);
  return createHash("sha256")
    .update(Buffer.from(ACTIVATION_READINESS_SNAPSHOT_DOMAIN, "utf8"))
    .update(Buffer.from(canonicalJson(normalized), "utf8"))
    .digest("hex");
}

export function createActivationReadinessSnapshot({
  stage,
  releaseSha,
  rpcEndpointSha256,
  deploymentIntentSha256,
  contractDeploymentReceiptSha256,
  cvmLaunchIntentSha256,
  finalAuthoritySha256 = null,
  chainEvidence,
  descriptorSha256ByDomain,
  checkedAt,
  expiresAt,
}) {
  return normalizeActivationReadinessSnapshot({
    schema: ACTIVATION_READINESS_SNAPSHOT_SCHEMA,
    truth_status: ACTIVATION_READINESS_TRUTH_STATUS,
    stage,
    release_sha: releaseSha,
    chain_id: Number(BASE_SEPOLIA_CHAIN_ID),
    rpc_endpoint_sha256: rpcEndpointSha256,
    secondary_rpc_endpoint_sha256: chainEvidence?.secondaryRpcEndpointSha256,
    rpc_origin_sha256: chainEvidence?.rpcOriginSha256,
    secondary_rpc_origin_sha256: chainEvidence?.secondaryRpcOriginSha256,
    dual_rpc_reconstruction_agreement:
      chainEvidence?.independentReconstructionRpcAgreement,
    dual_rpc_broadcast_transaction_agreement:
      chainEvidence?.broadcastTransactionRpcAgreement,
    dual_rpc_poststate_agreement: chainEvidence?.poststateRpcAgreement,
    deployment_intent_sha256: deploymentIntentSha256,
    contract_deployment_receipt_sha256: contractDeploymentReceiptSha256,
    cvm_launch_intent_sha256: cvmLaunchIntentSha256,
    final_authority_sha256: finalAuthoritySha256,
    snapshot_block_number: chainEvidence?.snapshotBlockNumber,
    snapshot_block_hash: chainEvidence?.snapshotBlockHash,
    snapshot_finality: chainEvidence?.snapshotFinality,
    finalized_recheck_block_number: chainEvidence?.finalizedRecheckBlockNumber,
    finalized_recheck_block_hash: chainEvidence?.finalizedRecheckBlockHash,
    immutable_provenance_contract_count:
      CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.length,
    immutable_provenance_sha256: activationReadinessImmutableProvenanceDigest(
      chainEvidence?.immutableProvenance,
    ),
    broadcast_transaction_count: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
    broadcast_transactions_sha256: chainEvidence?.broadcastTransactionsSha256,
    broadcast_transaction_provenance_sha256:
      activationReadinessBroadcastProvenanceDigest(
        chainEvidence?.broadcastTransactionProvenance,
      ),
    primary_broadcast_transaction_observations_sha256:
      chainEvidence?.primaryBroadcastTransactionObservationsSha256,
    secondary_broadcast_transaction_observations_sha256:
      chainEvidence?.secondaryBroadcastTransactionObservationsSha256,
    independent_reconstruction_sha256:
      chainEvidence?.independentReconstructionSha256,
    poststate_mode: chainEvidence?.poststateMode,
    poststate_contract_count: 6,
    poststates_sha256: activationReadinessPoststatesDigest(
      chainEvidence?.poststates,
      chainEvidence?.poststateMode,
    ),
    primary_poststate_observations_sha256:
      chainEvidence?.primaryPoststateObservationsSha256,
    secondary_poststate_observations_sha256:
      chainEvidence?.secondaryPoststateObservationsSha256,
    stateless_poststate_exception: CONTRACT_STATELESS_POSTSTATE_EXCEPTION,
    descriptor_raw_bytes_sha256_by_domain: { ...descriptorSha256ByDomain },
    checked_at: checkedAt,
    expires_at: expiresAt,
    authorized_next_actions: [...(ACTIVATION_READINESS_AUTHORIZED_ACTIONS[stage] || [])],
    immediate_recheck: { ...ACTIVATION_READINESS_IMMEDIATE_RECHECK },
    execution_boundary: {
      ...(ACTIVATION_READINESS_EXECUTION_BOUNDARY[stage] || {}),
      blocker_codes: [
        ...(ACTIVATION_READINESS_EXECUTION_BOUNDARY[stage]?.blocker_codes || []),
      ],
    },
    read_only: true,
    remote_state_mutated: false,
    raw_secret_egress: false,
  });
}

export function validateActivationReadinessSnapshot(value, expected, {
  nowMs,
} = {}) {
  const normalized = normalizeActivationReadinessSnapshot(value);
  const expectedFinalAuthority = expected.stage === "cvm_launch"
    ? null
    : expected.finalAuthoritySha256;
  const expectedDescriptorHashes = Object.fromEntries(
    CVM_TOPOLOGY_DOMAINS.map((domain) => [domain, expected.descriptorSha256ByDomain?.[domain]]),
  );
  if (normalized.stage !== expected.stage
    || normalized.release_sha !== expected.releaseSha
    || normalized.rpc_endpoint_sha256 !== expected.rpcEndpointSha256
    || normalized.secondary_rpc_endpoint_sha256
      !== expected.chainEvidence?.secondaryRpcEndpointSha256
    || normalized.rpc_origin_sha256 !== expected.chainEvidence?.rpcOriginSha256
    || normalized.secondary_rpc_origin_sha256
      !== expected.chainEvidence?.secondaryRpcOriginSha256
    || normalized.dual_rpc_reconstruction_agreement
      !== expected.chainEvidence?.independentReconstructionRpcAgreement
    || normalized.dual_rpc_broadcast_transaction_agreement
      !== expected.chainEvidence?.broadcastTransactionRpcAgreement
    || normalized.dual_rpc_poststate_agreement
      !== expected.chainEvidence?.poststateRpcAgreement
    || normalized.deployment_intent_sha256 !== expected.deploymentIntentSha256
    || normalized.contract_deployment_receipt_sha256
      !== expected.contractDeploymentReceiptSha256
    || normalized.cvm_launch_intent_sha256 !== expected.cvmLaunchIntentSha256
    || normalized.final_authority_sha256 !== expectedFinalAuthority
    || normalized.snapshot_block_number !== expected.chainEvidence?.snapshotBlockNumber
    || normalized.snapshot_block_hash !== expected.chainEvidence?.snapshotBlockHash
    || normalized.snapshot_finality !== expected.chainEvidence?.snapshotFinality
    || normalized.finalized_recheck_block_number
      !== expected.chainEvidence?.finalizedRecheckBlockNumber
    || normalized.finalized_recheck_block_hash
      !== expected.chainEvidence?.finalizedRecheckBlockHash
    || normalized.immutable_provenance_sha256
      !== activationReadinessImmutableProvenanceDigest(
        expected.chainEvidence?.immutableProvenance,
      )
    || normalized.broadcast_transactions_sha256
      !== expected.chainEvidence?.broadcastTransactionsSha256
    || normalized.broadcast_transaction_provenance_sha256
      !== activationReadinessBroadcastProvenanceDigest(
        expected.chainEvidence?.broadcastTransactionProvenance,
      )
    || normalized.primary_broadcast_transaction_observations_sha256
      !== expected.chainEvidence?.primaryBroadcastTransactionObservationsSha256
    || normalized.secondary_broadcast_transaction_observations_sha256
      !== expected.chainEvidence?.secondaryBroadcastTransactionObservationsSha256
    || normalized.primary_poststate_observations_sha256
      !== expected.chainEvidence?.primaryPoststateObservationsSha256
    || normalized.secondary_poststate_observations_sha256
      !== expected.chainEvidence?.secondaryPoststateObservationsSha256
    || normalized.independent_reconstruction_sha256
      !== expected.chainEvidence?.independentReconstructionSha256
    || normalized.poststate_mode !== expected.chainEvidence?.poststateMode
    || normalized.poststates_sha256 !== activationReadinessPoststatesDigest(
      expected.chainEvidence?.poststates,
      expected.chainEvidence?.poststateMode,
    )
    || canonicalJson(normalized.descriptor_raw_bytes_sha256_by_domain)
      !== canonicalJson(expectedDescriptorHashes)) {
    throw new Error("activation readiness snapshot does not bind current evidence");
  }
  const checkedAtMs = Date.parse(normalized.checked_at);
  const expiresAtMs = Date.parse(normalized.expires_at);
  if (!Number.isSafeInteger(nowMs)
    || nowMs < 1
    || checkedAtMs > nowMs + 5_000
    || nowMs >= expiresAtMs
    || nowMs - checkedAtMs > ACTIVATION_READINESS_MAX_LIFETIME_MS) {
    throw new Error("activation readiness snapshot is not currently fresh");
  }
  return {
    valid: true,
    sha256: `sha256:${activationReadinessSnapshotDigest(normalized)}`,
    checkedAtMs,
    expiresAtMs,
  };
}

function semanticLiveActivationReceiptValid(receipt, {
  deploymentIntentSha256,
  reviewerAuthorityGenesisAcceptanceSha256,
  ceremonyAuthorizationSha256,
  liveActivationAuthoritySha256,
  runtimeAuthorityDependencySha256,
  releaseSha,
} = {}) {
  return exactObject(receipt, [
    "ceremony_authorization_sha256",
    "chain_id",
    "compute_workload_activation_observation_sha256",
    "compute_workload_browser_binding_sha256",
    "deployment_intent_sha256",
    "frontend_build_candidate_receipt_sha256",
    "frontend_build_sha256",
    "live_activation_authority_sha256",
    "raw_secret_egress",
    "release_env_sha256",
    "release_inputs_sha256",
    "release_sha",
    "reviewer_authority_genesis_acceptance_sha256",
    "runtime_authority_dependency_sha256",
    "schema",
    "status",
    "truth_status",
  ])
    && receipt.schema === SEMANTIC_VALIDATION_SCHEMA
    && receipt.status === SEMANTIC_VALIDATION_STATUS
    && receipt.truth_status === SEMANTIC_VALIDATION_TRUTH_STATUS
    && receipt.release_sha === releaseSha
    && receipt.chain_id === Number(BASE_SEPOLIA_CHAIN_ID)
    && receipt.deployment_intent_sha256 === deploymentIntentSha256
    && receipt.reviewer_authority_genesis_acceptance_sha256
      === reviewerAuthorityGenesisAcceptanceSha256
    && receipt.ceremony_authorization_sha256 === ceremonyAuthorizationSha256
    && receipt.live_activation_authority_sha256 === liveActivationAuthoritySha256
    && receipt.runtime_authority_dependency_sha256
      === runtimeAuthorityDependencySha256
    && [
      receipt.deployment_intent_sha256,
      receipt.reviewer_authority_genesis_acceptance_sha256,
      receipt.ceremony_authorization_sha256,
      receipt.live_activation_authority_sha256,
      receipt.runtime_authority_dependency_sha256,
      receipt.compute_workload_activation_observation_sha256,
      receipt.compute_workload_browser_binding_sha256,
      receipt.frontend_build_candidate_receipt_sha256,
      receipt.release_inputs_sha256,
      receipt.release_env_sha256,
      receipt.frontend_build_sha256,
    ].every(isNonzeroSha256)
    && receipt.raw_secret_egress === false;
}

export function canonicalSevenCvmAuthorityValidationValid(value, {
  authorityStage,
  releaseSha,
  deploymentIntentSha256,
} = {}) {
  const expectedMode = authorityStage === "release_ceremony"
    ? CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_MODE
    : authorityStage === "live_activation"
      ? CANONICAL_SEVEN_CVM_AUTHORITY_HISTORICAL_MODE
      : "";
  const expectedTruth = expectedMode === CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_MODE
    ? CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_TRUTH
    : expectedMode === CANONICAL_SEVEN_CVM_AUTHORITY_HISTORICAL_MODE
      ? CANONICAL_SEVEN_CVM_AUTHORITY_HISTORICAL_TRUTH
      : "";
  return Boolean(expectedMode)
    && exactObject(value, [
      "allSevenMachineVerified",
      "authorityChainSubjectSha256",
      "canonicalDependencyChainVerified",
      "ceremonyNonce",
      "chainId",
      "dependencyGraphSha256",
      "deploymentIntentSha256",
      "descriptorRuntimeAuthoritySha256",
      "evidenceMode",
      "historicalTranscriptFileSetSha256",
      "measurementPolicySetSha256",
      "rawQuotePersisted",
      "rawSecretEgress",
      "releaseAuthoritySha256",
      "releaseSha",
      "sevenCvmLaunchCompletionReceiptSha256",
      "sevenCvmVerifiedEvidenceSetSha256",
      "source",
      "status",
      "truthStatus",
    ])
    && value.source === CANONICAL_SEVEN_CVM_AUTHORITY_VALIDATION_SOURCE
    && value.status === CANONICAL_SEVEN_CVM_AUTHORITY_VALIDATION_STATUS
    && value.truthStatus === expectedTruth
    && value.evidenceMode === expectedMode
    && value.chainId === Number(BASE_SEPOLIA_CHAIN_ID)
    && value.releaseSha === releaseSha
    && value.deploymentIntentSha256 === deploymentIntentSha256
    && /^[0-9a-f]{40}$/.test(String(value.releaseSha))
    && isNonzeroBytes32(value.ceremonyNonce)
    && [
      value.authorityChainSubjectSha256,
      value.dependencyGraphSha256,
      value.deploymentIntentSha256,
      value.descriptorRuntimeAuthoritySha256,
      value.historicalTranscriptFileSetSha256,
      value.measurementPolicySetSha256,
      value.releaseAuthoritySha256,
      value.sevenCvmLaunchCompletionReceiptSha256,
      value.sevenCvmVerifiedEvidenceSetSha256,
    ].every(isNonzeroSha256)
    && value.allSevenMachineVerified === true
    && value.canonicalDependencyChainVerified === true
    && value.rawQuotePersisted === false
    && value.rawSecretEgress === false;
}

function boundedString(value, maximum = 512) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximum
    && value === value.trim()
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function positiveIntegerString(value) {
  return boundedString(value, 128) && /^[1-9][0-9]*$/.test(value);
}

function exactHttpsUrl(value, origin, exactPath) {
  if (!boundedString(value, 1024)) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:"
      && parsed.origin === origin
      && parsed.pathname === exactPath
      && !parsed.username
      && !parsed.password
      && !parsed.search
      && !parsed.hash;
  } catch {
    return false;
  }
}

export function inspectImageRelease(value) {
  const invalid = {
    valid: false, releaseSha: "", sourceRef: "", generatedAt: "", images: [],
  };
  const topKeys = [
    "schema",
    "release_sha",
    "source_ref",
    "generated_at",
    "source_repository",
    "signer_workflow",
    "workflow_run_id",
    "workflow_run_url",
    "platform",
    "images",
  ];
  if (!exactObject(value, topKeys) || value.schema !== IMAGE_RELEASE_SCHEMA) return invalid;
  if (!/^[0-9a-f]{40}$/.test(value.release_sha)) return invalid;
  if (!/^(?:refs\/heads\/main|refs\/tags\/v[0-9][0-9A-Za-z._-]*)$/.test(value.source_ref)) {
    return invalid;
  }
  if (!boundedString(value.generated_at, 64)) return invalid;
  const generated = new Date(value.generated_at);
  if (Number.isNaN(generated.getTime()) || generated.toISOString() !== value.generated_at) return invalid;
  if (value.source_repository !== EXPECTED_GITHUB_REPOSITORY) return invalid;
  if (value.signer_workflow !== EXPECTED_GITHUB_WORKFLOW) return invalid;
  if (!positiveIntegerString(value.workflow_run_id)) return invalid;
  if (!exactHttpsUrl(
    value.workflow_run_url,
    "https://github.com",
    `/${EXPECTED_GITHUB_REPOSITORY}/actions/runs/${value.workflow_run_id}`,
  )) return invalid;
  if (value.platform !== EXPECTED_PLATFORM) return invalid;
  if (!Array.isArray(value.images) || value.images.length !== REQUIRED_IMAGE_SUFFIXES.length) {
    return invalid;
  }
  if (!value.images.every((image, index) => image?.name === REQUIRED_IMAGE_SUFFIXES[index])) {
    return invalid;
  }

  const normalizedImages = [];
  for (const [index, image] of value.images.entries()) {
    if (!exactObject(image, [
      "name",
      "repository",
      "digest",
      "image",
      "platform",
      "sbom_artifact",
      "provenance_subject",
      "attestations",
      "verification",
    ])) return invalid;
    const name = REQUIRED_IMAGE_SUFFIXES[index];
    const repository = `${EXPECTED_IMAGE_PREFIX}${name}`;
    if (image.repository !== repository || image.platform !== EXPECTED_PLATFORM) return invalid;
    if (!/^sha256:[0-9a-f]{64}$/.test(image.digest)) return invalid;
    if (image.image !== `${repository}@${image.digest}`) return invalid;
    if (!exactObject(image.sbom_artifact, ["filename", "sha256"])) return invalid;
    if (
      image.sbom_artifact.filename !== `${name}.spdx.json`
      || !/^[0-9a-f]{64}$/.test(image.sbom_artifact.sha256)
    ) return invalid;
    if (!exactObject(image.provenance_subject, ["name", "digest"])) return invalid;
    if (
      image.provenance_subject.name !== repository
      || image.provenance_subject.digest !== image.digest
    ) return invalid;
    if (!exactObject(image.attestations, ["provenance", "sbom"])) return invalid;
    for (const [kind, predicate] of [
      ["provenance", "https://slsa.dev/provenance/v1"],
      ["sbom", "https://spdx.dev/Document/v2.3"],
    ]) {
      const attestation = image.attestations[kind];
      if (!exactObject(attestation, ["predicate_type", "id", "url"])) return invalid;
      if (attestation.predicate_type !== predicate || !positiveIntegerString(attestation.id)) {
        return invalid;
      }
      if (!exactHttpsUrl(
        attestation.url,
        "https://github.com",
        `/${EXPECTED_GITHUB_REPOSITORY}/attestations/${attestation.id}`,
      )) return invalid;
    }
    if (!exactObject(image.verification, [
      "repo",
      "signer_workflow",
      "source_digest",
      "source_ref",
      "provenance_attestation",
      "sbom_attestation",
    ])) return invalid;
    if (
      image.verification.repo !== EXPECTED_GITHUB_REPOSITORY
      || image.verification.signer_workflow !== EXPECTED_GITHUB_WORKFLOW
      || image.verification.source_digest !== value.release_sha
      || image.verification.source_ref !== value.source_ref
      || image.verification.provenance_attestation !== "verified"
      || image.verification.sbom_attestation !== "verified"
    ) return invalid;
    normalizedImages.push(image.image);
  }
  return {
    valid: true,
    releaseSha: value.release_sha,
    sourceRef: value.source_ref,
    generatedAt: value.generated_at,
    images: normalizedImages,
  };
}

function exactStringArray(value, expected) {
  return Array.isArray(value)
    && value.length === expected.length
    && value.every((item, index) => item === expected[index]);
}

export function inspectCvmTopology(value) {
  const invalid = {
    valid: false, releaseSha: "", sourceRef: "", generatedAt: "", domains: {},
  };
  if (!exactObject(value, [
    "schema",
    "status",
    "release_sha",
    "source_ref",
    "generated_at",
    "deploymentIntentSha256",
    "deploymentIntent",
    "image_manifest",
    "image_manifest_attestation",
    "trust_domains",
    "checks",
  ])) return invalid;
  if (value.schema !== CVM_TOPOLOGY_SCHEMA || value.status !== "rendered_not_deployed") return invalid;
  if (!/^[0-9a-f]{40}$/.test(value.release_sha)) return invalid;
  if (!/^(?:refs\/heads\/main|refs\/tags\/v[0-9][0-9A-Za-z._-]*)$/.test(value.source_ref)) {
    return invalid;
  }
  if (!boundedString(value.generated_at, 64)) return invalid;
  const generated = new Date(value.generated_at);
  if (Number.isNaN(generated.getTime()) || generated.toISOString() !== value.generated_at) {
    return invalid;
  }
  if (!isNonzeroSha256(value.deploymentIntentSha256)) return invalid;
  if (!exactObject(value.deploymentIntent, ["file", "sha256", "schema"])) return invalid;
  if (
    value.deploymentIntent.file !== "dnai-deployment-intent-core.json"
    || !/^[0-9a-f]{64}$/.test(value.deploymentIntent.sha256)
    || value.deploymentIntent.schema !== DEPLOYMENT_INTENT_CORE_SCHEMA
    || value.deploymentIntentSha256 !== `sha256:${value.deploymentIntent.sha256}`
  ) return invalid;
  if (!exactObject(value.image_manifest, ["file", "sha256", "schema"])) return invalid;
  if (
    value.image_manifest.file !== "dnai-tee-image-release.json"
    || !/^[0-9a-f]{64}$/.test(value.image_manifest.sha256)
    || value.image_manifest.schema !== IMAGE_RELEASE_SCHEMA
  ) return invalid;
  if (!exactObject(value.image_manifest_attestation, [
    "file",
    "sha256",
    "predicate_type",
  ])) return invalid;
  if (
    value.image_manifest_attestation.file !== "dnai-tee-image-release.bundle.json"
    || !/^[0-9a-f]{64}$/.test(value.image_manifest_attestation.sha256)
    || value.image_manifest_attestation.predicate_type
      !== RELEASE_MANIFEST_PROVENANCE_PREDICATE
  ) return invalid;
  if (!exactObject(value.trust_domains, CVM_TOPOLOGY_DOMAINS)) return invalid;
  const domainPolicy = {
    main_runtime_cvm: {
      fields: [
        "compose",
        "sha256",
        "services",
        "images",
        "compute_execution",
        "deal_settlement",
        "email_oracle_consumer_policy",
      ],
      compose: "dnai-main-runtime.phala.yaml",
      services: REQUIRED_PRODUCTION_SERVICES,
      imageCount: 3,
    },
    ...Object.fromEntries(Object.entries(QVL_DOMAINS).map(([name, policy]) => [name, {
      fields: [
        "compose",
        "sha256",
        "services",
        "images",
        "qvl_context",
        "runtime_policy",
      ],
      compose: policy.compose,
      services: REQUIRED_QVL_SERVICES,
      imageCount: 1,
      qvlContext: policy.context,
    }])),
    independent_metering_cvm: {
      fields: ["compose", "sha256", "services", "images", "runtime_policy"],
      compose: "dnai-independent-metering.phala.yaml",
      services: REQUIRED_METERING_SERVICES,
      imageCount: 1,
    },
  };
  for (const [name, policy] of Object.entries(domainPolicy)) {
    const domain = value.trust_domains[name];
    if (!exactObject(domain, policy.fields)) return invalid;
    if (
      domain.compose !== policy.compose
      || !/^[0-9a-f]{64}$/.test(domain.sha256)
      || !exactStringArray(domain.services, policy.services)
      || !Array.isArray(domain.images)
      || domain.images.length !== policy.imageCount
      || !domain.images.every((image) => IMAGE_PATTERN.test(image))
      || (policy.qvlContext && domain.qvl_context !== policy.qvlContext)
    ) return invalid;
    const runtimePolicyKeys = policy.qvlContext
      ? QVL_NUMERIC_ENVIRONMENT_KEYS
      : name === "independent_metering_cvm"
        ? METERING_NUMERIC_ENVIRONMENT_KEYS
        : null;
    if (runtimePolicyKeys && (
      !exactObject(domain.runtime_policy, runtimePolicyKeys)
      || runtimePolicyKeys.some((key) => !boundedString(domain.runtime_policy[key], 128))
    )) return invalid;
  }
  const descriptorHashes = Object.values(value.trust_domains).map((domain) => domain.sha256);
  if (new Set(descriptorHashes).size !== descriptorHashes.length) return invalid;
  if (
    value.trust_domains.main_runtime_cvm.compute_execution
    !== "disabled_provider_contract_unavailable"
    || value.trust_domains.main_runtime_cvm.deal_settlement
      !== "disabled_confidential_evaluator_required"
    || value.trust_domains.main_runtime_cvm.email_oracle_consumer_policy
      !== "required_onchain_exact_release_binding"
  ) return invalid;
  if (!exactObject(value.checks, [
    "literal_digest_pins",
    "linux_amd64_only",
    "local_build_contexts",
    "seven_cvm_descriptors",
    "purpose_separated_qvl_descriptors",
    "raw_secret_values_embedded",
    "deployment_attempted",
    "tdx_verification_claimed",
  ])) return invalid;
  const expectedChecks = {
    literal_digest_pins: true,
    linux_amd64_only: true,
    local_build_contexts: false,
    seven_cvm_descriptors: true,
    purpose_separated_qvl_descriptors: true,
    raw_secret_values_embedded: false,
    deployment_attempted: false,
    tdx_verification_claimed: false,
  };
  if (Object.entries(expectedChecks).some(([key, expected]) => value.checks[key] !== expected)) {
    return invalid;
  }
  return {
    valid: true,
    releaseSha: value.release_sha,
    sourceRef: value.source_ref,
    generatedAt: value.generated_at,
    deploymentIntentSha256: value.deploymentIntentSha256,
    manifestSha256: value.image_manifest.sha256,
    manifestAttestationSha256: value.image_manifest_attestation.sha256,
    domains: value.trust_domains,
  };
}

function roleCollisionNames(env, requiredRoleKeys = REQUIRED_ROLE_KEYS) {
  const roles = requiredRoleKeys
    .filter((name) => isNonzeroAddress(env[name]))
    .map((name) => [name, clean(env[name]).toLowerCase()]);
  const collisions = [];
  for (let left = 0; left < roles.length; left += 1) {
    for (let right = left + 1; right < roles.length; right += 1) {
      if (roles[left][1] === roles[right][1]) {
        collisions.push(`${roles[left][0]} + ${roles[right][0]}`);
      }
    }
  }
  return collisions;
}

function imageSuffix(image) {
  const withoutDigest = String(image).split("@", 1)[0];
  return withoutDigest.slice(withoutDigest.lastIndexOf("/") + 1);
}

function sameStringSet(actual, expected) {
  if (!Array.isArray(actual)) return false;
  return actual.length === expected.length
    && [...actual].sort().every((value, index) => value === [...expected].sort()[index]);
}

function serviceNetworks(service) {
  const networks = service?.networks ?? [];
  if (Array.isArray(networks) && networks.every((name) => typeof name === "string")) {
    return networks;
  }
  if (networks && typeof networks === "object" && !Array.isArray(networks)) {
    return Object.keys(networks);
  }
  return null;
}

function reviewedMountsOnly(service) {
  const volumes = service?.volumes ?? [];
  if (!Array.isArray(volumes)) return false;
  return volumes.every((mount) => {
    if (typeof mount === "string") {
      const [source] = mount.split(":", 1);
      return !source.startsWith("/")
        || mount === "/var/run/dstack.sock:/var/run/dstack.sock:ro";
    }
    if (!mount || typeof mount !== "object" || Array.isArray(mount)) return false;
    if (mount.type === "volume") return true;
    return mount.type === "bind"
      && mount.source === "/var/run/dstack.sock"
      && mount.target === "/var/run/dstack.sock"
      && mount.read_only === true
      && Object.keys(mount).length === 4;
  });
}

function serviceSecurityValid(domain, name, service) {
  if (!service || typeof service !== "object" || "build" in service) return false;
  if (service.privileged === true || "devices" in service || "device_cgroup_rules" in service) {
    return false;
  }
  const networkMode = clean(service.network_mode);
  if (networkMode === "host" || /^(?:service|container):/.test(networkMode)) return false;
  if (["pid", "ipc", "uts", "userns_mode"].some((key) => clean(service[key]) === "host")) {
    return false;
  }
  const expectedCapAdd = domain === "main" && name === "neko"
    ? ["SYS_ADMIN"]
    : domain === "metering" && name === "state-init"
      ? ["CHOWN"]
      : [];
  if (!sameStringSet(service.cap_add ?? [], expectedCapAdd)) return false;
  if (!sameStringSet(service.cap_drop, ["ALL"])) return false;
  if (!sameStringSet(service.security_opt, ["no-new-privileges:true"])) return false;
  if (!(domain === "main" && name === "neko") && service.read_only !== true) return false;
  if (!reviewedMountsOnly(service)) return false;
  const expectedPorts = domain === "main" && name === "delegate"
    ? ["8080:8080"]
    : domain !== "main" && name === (domain === "metering" ? "metering" : "qvl")
      ? ["8443:8443"]
      : [];
  return sameStringSet(service.ports ?? [], expectedPorts);
}

function composeSecurityValid(domain, compose) {
  if (compose?.valid !== true || !compose.document) return false;
  return Object.entries(compose.document.services || {})
    .every(([name, service]) => serviceSecurityValid(domain, name, service));
}

function releaseMetadataValid(compose, domain, releaseSha, sourceRef) {
  const value = compose?.document?.["x-dnai-release"];
  return exactObject(value, [
    "schema",
    "release_sha",
    "source_ref",
    "platform",
    "trust_domain",
    "deployment_status",
  ])
    && value.schema === CVM_TOPOLOGY_SCHEMA
    && value.release_sha === releaseSha
    && value.source_ref === sourceRef
    && value.platform === EXPECTED_PLATFORM
    && value.trust_domain === domain
    && value.deployment_status === "rendered_not_deployed";
}

export function buildPreflightReport(snapshot) {
  const env = snapshot.env || {};
  const checks = [];

  checks.push(check(
    "safety.read_only",
    "pass",
    "This preflight uses an allowlisted read-only probe set and never unlocks a keystore, broadcasts, deploys, logs in, or changes remote state.",
  ));
  checks.push(check(
    "safety.env_mode",
    snapshot.files?.env?.exists && snapshot.files.env.mode === 0o600 ? "pass" : "fail",
    snapshot.files?.env?.exists && snapshot.files.env.mode === 0o600
      ? "The local environment file is present with mode 0600."
      : "The local environment file is missing or is not mode 0600.",
    "Create the untracked environment file and chmod it to 0600.",
  ));

  for (const tool of REQUIRED_TOOLS) {
    const phalaDiagnosticIdentity = tool !== "phala"
      || (exactObject(snapshot.toolVersions?.phala, ["valid", "version", "source"])
        && snapshot.toolVersions.phala.valid === true
        && snapshot.toolVersions.phala.version === "1.1.19"
        && snapshot.toolVersions.phala.source === "installed_package_manifest");
    const present = snapshot.tools?.[tool] === true && phalaDiagnosticIdentity;
    checks.push(check(
      `tool.${tool}`,
      present ? "pass" : "fail",
      present
        ? tool === "phala"
          ? "The Phala CLI 1.1.19 package identity is installed for diagnostics only; it is never accepted for prepare or commit."
          : `${tool} is installed.`
        : tool === "phala"
          ? "The diagnostic Phala CLI executable or exact 1.1.19 package-manifest identity is unavailable."
          : `${tool} is not available on PATH.`,
      `Install ${tool} before activation.`,
    ));
  }

  const headValid = /^[0-9a-f]{40}$/i.test(clean(snapshot.git?.head));
  checks.push(check(
    "source.head",
    headValid ? "pass" : "fail",
    headValid ? "Git HEAD resolves to a full commit SHA." : "Git HEAD could not be resolved.",
    "Run the preflight from a valid repository checkout.",
  ));
  checks.push(check(
    "source.clean",
    snapshot.git?.dirty === false ? "pass" : "fail",
    snapshot.git?.dirty === false
      ? "The source worktree is clean."
      : "The source worktree is dirty; live contract, image, CVM, and Pages release provenance is blocked.",
    "Commit and review the exact release source, then rerun the preflight.",
  ));
  const releaseSha = clean(env.RELEASE_SHA).toLowerCase();
  const releaseMatches = /^[0-9a-f]{40}$/.test(releaseSha)
    && releaseSha === clean(snapshot.git?.head).toLowerCase();
  checks.push(check(
    "source.release_sha",
    releaseMatches ? "pass" : "fail",
    releaseMatches
      ? "RELEASE_SHA is a full SHA matching HEAD."
      : "RELEASE_SHA is missing, malformed, or does not match HEAD.",
    "Set RELEASE_SHA to the exact reviewed clean commit.",
  ));

  const authorityStage = clean(snapshot.authorityStage || "live_activation");
  const authorityStageValid = [
    "fresh_deployment",
    "cvm_launch",
    "release_ceremony",
    "live_activation",
  ].includes(authorityStage);
  const liveActivation = authorityStage === "live_activation";
  const releaseCeremony = authorityStage === "release_ceremony";
  const cvmLaunch = authorityStage === "cvm_launch";
  const freshDeployment = authorityStage === "fresh_deployment";
  const measuredAuthorityStage = releaseCeremony || liveActivation;
  const preMeasuredAuthority = freshDeployment || cvmLaunch;
  checks.push(check(
    "authority.stage",
    authorityStageValid ? "pass" : "fail",
    authorityStageValid
      ? liveActivation
        ? "This report is evaluating post-ceremony live-activation authority before the Cloudflare release."
        : releaseCeremony
          ? "This report is evaluating measured final authority before any release-ceremony contract mutation."
          : cvmLaunch
            ? "This report is evaluating reviewed CVM-launch authority after the fresh contract suite and before any CVM deployment."
            : "This report is evaluating predeployment authority and cannot claim postdeployment release authority."
      : "The authority stage is missing or unsupported.",
    "Use fresh_deployment before broadcast, cvm_launch before Phala deployment, release_ceremony before contract activation mutations, and live_activation only after that ceremony.",
  ));

  const releaseAuthority = snapshot.releaseAuthority || {};
  const deploymentIntentSha256 = clean(releaseAuthority.deploymentIntentSha256);
  const reviewerAuthorityGenesisAcceptanceSha256 = clean(
    releaseAuthority.reviewerAuthorityGenesisAcceptanceSha256,
  );
  const deploymentIntentValid = releaseAuthority.deploymentIntentValid === true
    && releaseAuthority.deploymentIntentFileHashBound === true
    && releaseAuthority.deploymentIntentFreshChallengeStateValid === true
    && isNonzeroSha256(deploymentIntentSha256)
    && isNonzeroSha256(reviewerAuthorityGenesisAcceptanceSha256);
  checks.push(check(
    "authority.deployment_intent",
    deploymentIntentValid ? "pass" : "fail",
    deploymentIntentValid
      ? "The canonical deployment intent binds exact file bytes and the expected empty, unpaused fresh ChallengeRegistry state."
      : "The deployment intent is missing, invalid, file-unbound, or does not project the exact empty, unpaused fresh ChallengeRegistry state.",
    "Create and validate the immutable deployment-intent core before any contract broadcast or CVM deployment.",
  ));

  const authorityReleaseSha = clean(releaseAuthority.releaseSha).toLowerCase();
  const deploymentIntentSourceBound = deploymentIntentValid
    && releaseAuthority.gitObjectIsCommit === true
    && authorityReleaseSha === releaseSha
    && authorityReleaseSha === clean(snapshot.git?.head).toLowerCase()
    && Number.isSafeInteger(releaseAuthority.commitTime)
    && releaseAuthority.commitTime > 0;
  checks.push(check(
    "authority.deployment_intent_source",
    deploymentIntentSourceBound ? "pass" : "fail",
    deploymentIntentSourceBound
      ? "The deployment intent names the exact clean release commit and Git confirms that object is a commit."
      : "The deployment-intent release SHA, Git object type, environment SHA, or HEAD does not match exactly.",
    "Regenerate and review the deployment intent for the exact clean release commit.",
  ));

  const intentProjection = releaseAuthority.deploymentIntentEnvironmentProjection;
  const intentProjectionValid = intentProjection?.ok === true
    && Array.isArray(intentProjection.checkedKeys)
    && intentProjection.checkedKeys.length > 0
    && Array.isArray(intentProjection.mismatchKeys)
    && intentProjection.mismatchKeys.length === 0;
  checks.push(check(
    "authority.deployment_intent_environment_projection",
    intentProjectionValid ? "pass" : "fail",
    intentProjectionValid
      ? `All ${intentProjection.checkedKeys.length} public predeployment inputs equal the validated deployment-intent projection.`
      : "The deployment-intent-to-environment projection is incomplete or one or more public predeployment inputs differs.",
    "Implement complete cryptographic projection coverage and generate public predeployment inputs from the validated intent.",
  ));

  const cvmLaunchAuthority = snapshot.cvmLaunchAuthority || {};
  const cvmLaunchIntentSha256 = clean(cvmLaunchAuthority.sha256);
  const cvmLaunchIntentValid = cvmLaunchAuthority.valid === true
    && cvmLaunchAuthority.fileHashBound === true
    && isNonzeroSha256(cvmLaunchIntentSha256)
    && clean(cvmLaunchAuthority.deploymentIntentSha256) === deploymentIntentSha256
    && clean(cvmLaunchAuthority.releaseSha).toLowerCase() === authorityReleaseSha;
  checks.push(check(
    "authority.cvm_launch_intent",
    freshDeployment || cvmLaunchIntentValid ? "pass" : "fail",
    freshDeployment
      ? "CVM-launch intent is not accepted or required before the reviewed fresh contract deployment."
      : cvmLaunchIntentValid
        ? "The canonical CVM-launch intent is exact-file-bound and links the reviewed deployment intent to launch artifacts."
        : "The CVM-launch intent is missing, invalid, file-unbound, or linked to a different deployment intent or release source.",
    freshDeployment
      ? "After the fresh contract ledger exists, create and review the exact CVM-launch intent before deploying any CVM."
      : "Regenerate the CVM-launch intent from the exact fresh ledger, image evidence, and seven production descriptors.",
  ));

  const cvmExecutionBoundary = ACTIVATION_READINESS_EXECUTION_BOUNDARY.cvm_launch;
  const namedCvmExecutionBlockers = Array.isArray(
    cvmExecutionBoundary.blocker_codes,
  )
    ? cvmExecutionBoundary.blocker_codes.filter((code) => (
      typeof code === "string" && code.length > 0
    ))
    : [];
  const cvmExecutionRequired = !freshDeployment;
  const cvmExecutionAvailable = cvmExecutionBoundary.availability === true
    && cvmExecutionBoundary.reason_code === null
    && Array.isArray(cvmExecutionBoundary.blocker_codes)
    && cvmExecutionBoundary.blocker_codes.length === 0;
  checks.push(check(
    "authority.cvm_execution_boundary_availability",
    !cvmExecutionRequired || cvmExecutionAvailable ? "pass" : "fail",
    !cvmExecutionRequired
      ? "The CVM executor is not accepted or required for the reviewed contract-only deployment stage."
      : cvmExecutionAvailable
        ? "The reviewed CVM execution boundary is available with no unresolved adapter, key, journal, or public-value blockers."
        : `CVM execution is unavailable (${cvmExecutionBoundary.reason_code}); unresolved blocker count: ${namedCvmExecutionBlockers.length}; first blocker: ${namedCvmExecutionBlockers[0] || "none named"}.`,
    !cvmExecutionRequired
      ? "Complete the contract-only stage, then rerun the exact executor readiness checks before CVM launch."
      : "Use only the reviewed pinned SDK executor; do not use a manual SDK or Phala CLI mutation bypass.",
  ));

  const finalAuthoritySha256 = clean(releaseAuthority.finalAuthoritySha256);
  const finalAuthorityValid = releaseAuthority.finalAuthorityValid === true
    && releaseAuthority.finalAuthorityFileHashBound === true
    && isNonzeroSha256(finalAuthoritySha256)
    && clean(releaseAuthority.finalAuthorityDeploymentIntentSha256)
      === deploymentIntentSha256
    && cvmLaunchIntentValid
    && clean(releaseAuthority.finalAuthorityCvmLaunchIntentSha256)
      === cvmLaunchIntentSha256;
  checks.push(check(
    "authority.final_release_authority",
    preMeasuredAuthority || (measuredAuthorityStage && finalAuthorityValid) ? "pass" : "fail",
    freshDeployment
      ? "Final release authority is not accepted or required at the fresh-deployment stage; only reviewed intent can authorize deployment."
      : cvmLaunch
        ? "Final release authority is not accepted or required before CVMs launch and produce measurable runtime identities."
        : releaseCeremony
          ? finalAuthorityValid
            ? "The pre-mutation release ceremony is authorized by a digest-bound final authority linked to both earlier intents."
            : "The release ceremony lacks a valid final authority linked to the exact deployment and CVM-launch intents."
        : finalAuthorityValid
          ? "The canonical final authority is digest-bound and commits to both deployment and CVM-launch intents."
          : "Live activation lacks a valid final authority linked to the exact deployment and CVM-launch intents.",
    "After CVM deployment, measure the trust roots and create the canonical final authority linked to both reviewed intents.",
  ));

  const expectedReviewSubjectKind = measuredAuthorityStage
    ? "final_release_authority"
    : cvmLaunch
      ? "cvm_launch_intent"
      : "deployment_intent";
  const expectedReviewSubjectSha256 = measuredAuthorityStage
    ? finalAuthoritySha256
    : cvmLaunch
      ? cvmLaunchIntentSha256
      : deploymentIntentSha256;
  const stageReview = cvmLaunch ? cvmLaunchAuthority : releaseAuthority;
  const approvedAtMs = Date.parse(clean(stageReview.approvedAt));
  const expiresAtMs = Date.parse(clean(stageReview.expiresAt));
  const checkedAtMs = Number(stageReview.checkedAtMs);
  const currentReviewValid = authorityStageValid
    && stageReview.reviewEnvelopeValid === true
    && stageReview.reviewEnvelopeFileHashBound === true
    && isNonzeroSha256(stageReview.reviewEnvelopeSha256)
    && stageReview.reviewSubjectKind === expectedReviewSubjectKind
    && clean(stageReview.reviewSubjectSha256) === expectedReviewSubjectSha256
    && Number.isFinite(approvedAtMs)
    && Number.isFinite(expiresAtMs)
    && Number.isSafeInteger(checkedAtMs)
    && checkedAtMs > 0
    && Number.isSafeInteger(releaseAuthority.commitTime)
    && releaseAuthority.commitTime * 1_000 <= approvedAtMs
    && approvedAtMs <= checkedAtMs + 300_000
    && expiresAtMs > checkedAtMs
    && expiresAtMs > approvedAtMs
    && expiresAtMs - approvedAtMs <= 7 * 24 * 60 * 60 * 1_000;
  checks.push(check(
    "authority.current_review_envelope",
    currentReviewValid ? "pass" : "fail",
    currentReviewValid
      ? `The renewable review envelope currently binds the exact ${expectedReviewSubjectKind} subject after the release commit.`
      : "The review envelope is invalid, expired, future-dated, overlong, file-unbound, or names the wrong authority-stage subject.",
    "Renew the canonical review envelope for the exact stage subject and rerun preflight before its bounded expiry.",
  ));

  const reviewEvidenceSha256 = clean(stageReview.reviewEvidenceSha256);
  const reviewEvidenceValid = stageReview.reviewEvidenceValid === true
    && stageReview.reviewEvidenceFileHashBound === true
    && isNonzeroSha256(reviewEvidenceSha256);
  checks.push(check(
    "authority.review_evidence",
    reviewEvidenceValid ? "pass" : "fail",
    reviewEvidenceValid
      ? "The public review-evidence bytes match the digest declared by the current review envelope."
      : "The public review-evidence artifact is missing, malformed, zero-valued, or does not match the current envelope digest.",
    "Provide the exact bounded public review-evidence file declared by the current review envelope.",
  ));

  const candidate = snapshot.files?.releaseCandidate?.value;
  const candidateAuthority = candidate?.operator_policy;
  const releaseCore = snapshot.files?.releaseCore?.value;
  const ledgerIntentSha256 = clean(
    snapshot.files?.ledger?.value?.freshDeployment?.contractSuite
      ?.deploymentIntentSha256,
  );
  const descriptorSha256ByDomain = cvmLaunchAuthority.descriptorSha256ByDomain;
  const descriptorPinsValid = exactObject(
    descriptorSha256ByDomain,
    CVM_TOPOLOGY_DOMAINS,
  )
    && CVM_TOPOLOGY_DOMAINS.every((domain) => (
      isNonzeroSha256(descriptorSha256ByDomain[domain])
      && descriptorSha256ByDomain[domain]
        === `sha256:${clean(snapshot.topology?.domains?.[domain]?.sha256)}`
    ));
  let projectedContractDeploymentReceipt = null;
  let projectedContractDeploymentReceiptSha256 = "";
  try {
    const contractDeploymentReceiptAuthorityPins = {
      expectedDeploymentIntentSha256: deploymentIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        reviewerAuthorityGenesisAcceptanceSha256,
    };
    projectedContractDeploymentReceipt = projectFreshContractDeploymentReceipt(
      snapshot.files?.ledger?.value,
      {
        releaseSha: authorityReleaseSha,
        ...contractDeploymentReceiptAuthorityPins,
      },
    );
    projectedContractDeploymentReceiptSha256 =
      `sha256:${freshContractDeploymentReceiptDigest(
        projectedContractDeploymentReceipt,
        contractDeploymentReceiptAuthorityPins,
      )}`;
  } catch {
    projectedContractDeploymentReceipt = null;
    projectedContractDeploymentReceiptSha256 = "";
  }
  const contractDeploymentReceiptValid =
    cvmLaunchAuthority.contractDeploymentReceiptValid === true
    && Array.isArray(projectedContractDeploymentReceipt?.contracts)
    && projectedContractDeploymentReceipt.contracts.length
      === CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.length
    && cvmLaunchAuthority.contractDeploymentContractCount
      === CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.length
    && isNonzeroSha256(cvmLaunchAuthority.contractDeploymentReceiptSha256)
    && clean(cvmLaunchAuthority.contractDeploymentReceiptSha256)
      === projectedContractDeploymentReceiptSha256;
  const chainEvidence = snapshot.contractDeploymentChainEvidence || {};
  const canonicalContractCount = CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.length;
  const expectedPoststateMode = liveActivation
    ? "final_active_frozen"
    : (cvmLaunch || releaseCeremony)
      ? "fresh_fail_closed"
      : "";
  const contractDeploymentChainEvidenceValid = exactObject(chainEvidence, [
    "evidenceSource",
    "valid",
    "readOnly",
    "chainId",
    "secondaryChainId",
    "rpcEndpointSha256",
    "secondaryRpcEndpointSha256",
    "rpcOriginSha256",
    "secondaryRpcOriginSha256",
    "rpcEndpointsDistinct",
    "secondaryFinalizedSnapshotVerified",
    "secondaryFinalizedTagRechecked",
    "snapshotBlockNumber",
    "snapshotBlockHash",
    "snapshotFinality",
    "finalizedTagRechecked",
    "finalizedRecheckBlockNumber",
    "finalizedRecheckBlockHash",
    "snapshotBlockHashVerified",
    "commonSnapshotBlock",
    "contractCount",
    "transactionCount",
    "deployerMatchCount",
    "creationTransactionCount",
    "receiptCount",
    "successfulReceiptCount",
    "contractAddressMatchCount",
    "deploymentBlockMatchCount",
    "deploymentBlockHashMatchCount",
    "runtimeCodeMatchCount",
    "immutableProvenanceContractCount",
    "immutableProvenanceValid",
    "immutableProvenance",
    "broadcastTransactionCount",
    "broadcastTransactionValidCount",
    "broadcastTransactionsSha256",
    "broadcastTransactionProvenanceValid",
    "broadcastTransactionProvenance",
    "primaryBroadcastTransactionObservationsSha256",
    "secondaryBroadcastTransactionObservationsSha256",
    "broadcastTransactionRpcAgreement",
    "independentReconstructionValid",
    "independentReconstructionSha256",
    "independentReconstructionRpcAgreement",
    "secondaryRuntimeCodeMatchCount",
    "poststateMode",
    "poststateContractCount",
    "poststateValid",
    "poststates",
    "primaryPoststateObservationsSha256",
    "secondaryPoststateContractCount",
    "secondaryPoststateValid",
    "secondaryPoststateObservationsSha256",
    "poststateRpcAgreement",
    "statelessPoststateException",
  ])
    && chainEvidence.evidenceSource === "production_collector"
    && chainEvidence.valid === true
    && chainEvidence.readOnly === true
    && chainEvidence.chainId === Number(BASE_SEPOLIA_CHAIN_ID)
    && chainEvidence.secondaryChainId === Number(BASE_SEPOLIA_CHAIN_ID)
    && isNonzeroSha256(chainEvidence.rpcEndpointSha256)
    && isNonzeroSha256(chainEvidence.secondaryRpcEndpointSha256)
    && chainEvidence.secondaryRpcEndpointSha256 !== chainEvidence.rpcEndpointSha256
    && isNonzeroSha256(chainEvidence.rpcOriginSha256)
    && isNonzeroSha256(chainEvidence.secondaryRpcOriginSha256)
    && chainEvidence.secondaryRpcOriginSha256 !== chainEvidence.rpcOriginSha256
    && chainEvidence.rpcEndpointsDistinct === true
    && chainEvidence.secondaryFinalizedSnapshotVerified === true
    && chainEvidence.secondaryFinalizedTagRechecked === true
    && Number.isSafeInteger(chainEvidence.snapshotBlockNumber)
    && chainEvidence.snapshotBlockNumber > 0
    && isNonzeroBytes32(chainEvidence.snapshotBlockHash)
    && chainEvidence.snapshotBlockHash
      === clean(chainEvidence.snapshotBlockHash).toLowerCase()
    && chainEvidence.snapshotFinality === "rpc_finalized"
    && chainEvidence.finalizedTagRechecked === true
    && Number.isSafeInteger(chainEvidence.finalizedRecheckBlockNumber)
    && chainEvidence.finalizedRecheckBlockNumber >= chainEvidence.snapshotBlockNumber
    && isNonzeroBytes32(chainEvidence.finalizedRecheckBlockHash)
    && chainEvidence.finalizedRecheckBlockHash
      === clean(chainEvidence.finalizedRecheckBlockHash).toLowerCase()
    && chainEvidence.snapshotBlockHashVerified === true
    && chainEvidence.commonSnapshotBlock === true
    && [
      "contractCount",
      "transactionCount",
      "deployerMatchCount",
      "creationTransactionCount",
      "receiptCount",
      "successfulReceiptCount",
      "contractAddressMatchCount",
      "deploymentBlockMatchCount",
      "deploymentBlockHashMatchCount",
      "runtimeCodeMatchCount",
    ].every((key) => chainEvidence[key] === canonicalContractCount)
    && chainEvidence.immutableProvenanceContractCount === canonicalContractCount
    && chainEvidence.immutableProvenanceValid === true
    && (() => {
      try {
        normalizedReadinessProvenance(chainEvidence.immutableProvenance);
        return true;
      } catch {
        return false;
      }
    })()
    && chainEvidence.broadcastTransactionCount
      === FRESH_DEPLOYMENT_TRANSACTION_SPEC.length
    && chainEvidence.broadcastTransactionValidCount
      === FRESH_DEPLOYMENT_TRANSACTION_SPEC.length
    && chainEvidence.broadcastTransactionsSha256
      === projectedContractDeploymentReceipt?.broadcast_transactions_sha256
    && chainEvidence.broadcastTransactionProvenanceValid === true
    && isNonzeroSha256(
      chainEvidence.primaryBroadcastTransactionObservationsSha256,
    )
    && chainEvidence.primaryBroadcastTransactionObservationsSha256
      === chainEvidence.secondaryBroadcastTransactionObservationsSha256
    && chainEvidence.broadcastTransactionRpcAgreement === true
    && chainEvidence.independentReconstructionValid === true
    && isNonzeroSha256(chainEvidence.independentReconstructionSha256)
    && chainEvidence.independentReconstructionRpcAgreement === true
    && chainEvidence.secondaryRuntimeCodeMatchCount === canonicalContractCount
    && (() => {
      try {
        normalizedReadinessBroadcastProvenance(
          chainEvidence.broadcastTransactionProvenance,
        );
        return true;
      } catch {
        return false;
      }
    })()
    && chainEvidence.poststateMode === expectedPoststateMode
    && chainEvidence.poststateContractCount === 6
    && chainEvidence.poststateValid === true
    && isNonzeroSha256(chainEvidence.primaryPoststateObservationsSha256)
    && chainEvidence.secondaryPoststateContractCount === 6
    && chainEvidence.secondaryPoststateValid === true
    && chainEvidence.primaryPoststateObservationsSha256
      === chainEvidence.secondaryPoststateObservationsSha256
    && chainEvidence.poststateRpcAgreement === true
    && chainEvidence.statelessPoststateException
      === CONTRACT_STATELESS_POSTSTATE_EXCEPTION
    && (() => {
      try {
        normalizedReadinessPoststates(chainEvidence.poststates, expectedPoststateMode);
        return true;
      } catch {
        return false;
      }
    })();
  let activationReadinessValid = false;
  if (!freshDeployment && contractDeploymentChainEvidenceValid) {
    try {
      const validation = validateActivationReadinessSnapshot(
        snapshot.activationReadinessSnapshot,
        {
          stage: authorityStage,
          releaseSha: authorityReleaseSha,
          rpcEndpointSha256: chainEvidence.rpcEndpointSha256,
          deploymentIntentSha256,
          contractDeploymentReceiptSha256: projectedContractDeploymentReceiptSha256,
          cvmLaunchIntentSha256,
          finalAuthoritySha256,
          chainEvidence,
          descriptorSha256ByDomain,
        },
        { nowMs: Number(snapshot.activationReadinessValidationNowMs) },
      );
      activationReadinessValid = isNonzeroSha256(
        snapshot.activationReadinessSnapshotSha256,
      ) && clean(snapshot.activationReadinessSnapshotSha256) === validation.sha256;
    } catch {
      activationReadinessValid = false;
    }
  }
  const onlineStageEvidenceValid = contractDeploymentChainEvidenceValid
    && activationReadinessValid;
  checks.push(check(
    "authority.contract_deployment_chain_evidence",
    freshDeployment || onlineStageEvidenceValid ? "pass" : "fail",
    freshDeployment
      ? "Online contract-deployment evidence is not accepted or required before the reviewed fresh-suite broadcast."
      : onlineStageEvidenceValid
        ? liveActivation
          ? "A 120-second readiness snapshot binds two-RPC agreement for all 13 broadcasts, seven immutable deployments, six final states, and exact descriptor bytes."
          : "A 120-second readiness snapshot binds two-RPC agreement for all 13 broadcasts, seven immutable deployments, six fresh fail-closed states, and exact descriptor bytes."
        : "Base Sepolia dual-RPC evidence or its 120-second readiness snapshot is offline, stale, non-exact, divergent, file-unbound, or incomplete.",
    freshDeployment
      ? "After broadcast, independently verify the immutable deployment receipt before CVM launch."
      : "Run the online read-only verifier against two independent RPCs; any endpoint, reconstruction, receipt, code, block, or poststate disagreement must remain blocked.",
  ));
  const cvmLaunchArtifactHashesValid = [
    cvmLaunchAuthority.imageReleaseManifestSha256,
    cvmLaunchAuthority.imageAttestationBundleSha256,
    cvmLaunchAuthority.topologySha256,
  ].every(isNonzeroSha256)
    && clean(cvmLaunchAuthority.imageReleaseManifestSha256)
      === `sha256:${clean(snapshot.files?.imageRelease?.sha256)}`
    && clean(cvmLaunchAuthority.imageAttestationBundleSha256)
      === `sha256:${clean(snapshot.files?.imageReleaseAttestationBundle?.sha256)}`
    && clean(cvmLaunchAuthority.topologySha256)
      === `sha256:${clean(snapshot.files?.topology?.sha256)}`;
  const cvmLaunchArtifactsBound = cvmLaunchIntentValid
    && cvmLaunchAuthority.artifactBindingsValid === true
    && contractDeploymentReceiptValid
    && onlineStageEvidenceValid
    && cvmLaunchAuthority.imageReleaseValid === true
    && cvmLaunchAuthority.imageCount === 5
    && cvmLaunchAuthority.topologyValid === true
    && cvmLaunchAuthority.descriptorCount === CVM_TOPOLOGY_DOMAINS.length
    && cvmLaunchAuthority.descriptorHashesDistinct === true
    && cvmLaunchAuthority.productionPostureValid === true
    && snapshot.files?.ledger?.valid === true
    && snapshot.files?.imageRelease?.valid === true
    && snapshot.files?.imageReleaseAttestationBundle?.valid === true
    && snapshot.files?.topology?.valid === true
    && snapshot.imageRelease?.valid === true
    && snapshot.imageRelease?.images?.length === 5
    && snapshot.topology?.valid === true
    && ledgerIntentSha256 === deploymentIntentSha256
    && cvmLaunchArtifactHashesValid
    && descriptorPinsValid;
  const finalArtifactsBound = deploymentIntentValid
    && finalAuthorityValid
    && cvmLaunchArtifactsBound
    && snapshot.files?.releaseCandidate?.valid === true
    && snapshot.files?.releaseCore?.valid === true
    && snapshot.files?.ledger?.valid === true
    && candidate?.schema === "dnai.web-release.v4"
    && candidate?.deployment_intent_sha256 === deploymentIntentSha256
    && candidate?.cvm_launch_intent_sha256 === cvmLaunchIntentSha256
    && candidateAuthority?.runtime_authority_dependency_sha256
      === finalAuthoritySha256
    && isNonzeroSha256(candidateAuthority?.ceremony_authorization_sha256)
    && (liveActivation
      ? candidateAuthority?.schema === LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA
        && isNonzeroSha256(candidateAuthority?.live_activation_authority_sha256)
      : candidateAuthority?.schema === PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA
        && !Object.hasOwn(candidateAuthority, "live_activation_authority_sha256"))
    && releaseCore?.schema === FINAL_RELEASE_AUTHORITY_CORE_SCHEMA
    && releaseCore?.deployment_intent_sha256 === deploymentIntentSha256
    && releaseCore?.cvm_launch_intent_sha256 === cvmLaunchIntentSha256
    && ledgerIntentSha256 === deploymentIntentSha256;
  const releaseArtifactsBound = freshDeployment
    ? deploymentIntentValid
    : cvmLaunch
      ? cvmLaunchArtifactsBound
      : measuredAuthorityStage && finalArtifactsBound;
  checks.push(check(
    "authority.release_artifact_binding",
    releaseArtifactsBound ? "pass" : "fail",
    releaseArtifactsBound
      ? freshDeployment
        ? "Fresh-deployment authority stops at the reviewed intent and does not accept any existing ledger as broadcast evidence."
        : cvmLaunch
          ? "The reviewed launch intent binds the exact seven-contract ledger, five shared-image subjects, and seven distinct production descriptors."
          : releaseCeremony
            ? "The pre-mutation ceremony binds one exact intent, launch evidence, final authority, candidate, and current review/evidence chain."
            : "The post-ceremony live gate binds one exact intent, launch evidence, final authority, candidate, and current review/evidence chain."
      : freshDeployment
        ? "The reviewed deployment intent does not authorize the expected fresh contract state."
        : cvmLaunch
          ? "The CVM-launch intent, fresh ledger, five shared-image subjects, or seven production descriptor hashes do not match exactly."
          : "The measured intent, launch evidence, final authority, candidate, or current review does not share one exact authority chain.",
    freshDeployment
      ? "Correct and renew review of the deployment intent before any broadcast."
      : cvmLaunch
        ? "Regenerate the launch intent from stable-read artifacts and review it before deploying any CVM."
        : "Regenerate or reject the measured artifacts; do not combine authority evidence from different release stages.",
  ));

  const preMeasuredDeferredContractInputs = new Set([
    "DILIGENCE_RESULT_VERIFIER",
    "COMPUTE_VAULT_METERING_VERIFIER",
    "COMPUTE_VAULT_METERING_QVL_VERIFIER",
    "TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH",
  ]);
  for (const name of REQUIRED_CONTRACT_INPUTS) {
    const deferred = preMeasuredAuthority
      && preMeasuredDeferredContractInputs.has(name);
    let distinctRpcEndpoints = false;
    try {
      distinctRpcEndpoints = activationReadinessRpcEndpointDigest(
        env.BASE_SEPOLIA_RPC_URL,
      ) !== activationReadinessRpcEndpointDigest(
        env.BASE_SEPOLIA_SECONDARY_RPC_URL,
      ) && new URL(clean(env.BASE_SEPOLIA_RPC_URL)).origin.toLowerCase()
        !== new URL(clean(env.BASE_SEPOLIA_SECONDARY_RPC_URL)).origin.toLowerCase();
    } catch {
      distinctRpcEndpoints = false;
    }
    const valid = deferred || (
      validateContractInput(name, env[name])
      && (name !== "BASE_SEPOLIA_SECONDARY_RPC_URL" || distinctRpcEndpoints)
    );
    checks.push(check(
      `contract_input.${name.toLowerCase()}`,
      valid ? "pass" : "fail",
      deferred
        ? `${name} is not accepted or required before measured CVM authority exists.`
        : valid
        ? `${name} is present and structurally valid.`
        : `${name} is missing or structurally invalid.`,
      deferred
        ? `Set ${name} only through the reviewed postdeployment activation ceremony.`
        : `Populate ${name} with an independently reviewed value.`,
    ));
  }

  const fee = clean(env.COMPUTE_VAULT_DEVELOPER_FEE_BPS);
  const feeValid = isUnsignedInteger(fee) && BigInt(fee) <= 2_000n;
  checks.push(check(
    "contract_policy.compute_fee_cap",
    feeValid ? "pass" : "fail",
    feeValid
      ? "The Compute developer fee is within the deployment helper cap."
      : "The Compute developer fee exceeds the deployment helper cap or is malformed.",
    "Use an explicitly reviewed fee no greater than 2000 bps.",
  ));
  const delay = clean(env.EMAIL_ORACLE_UPGRADE_DELAY);
  const delayValid = isUnsignedInteger(delay)
    && BigInt(delay) >= 172_800n
    && BigInt(delay) <= 31_536_000n;
  checks.push(check(
    "contract_policy.oracle_delay",
    delayValid ? "pass" : "fail",
    delayValid
      ? "The EmailOracleAuth delay is within the production helper bounds."
      : "The EmailOracleAuth delay is outside the production helper bounds or malformed.",
    "Use a reviewed delay between 172800 and 31536000 seconds.",
  ));
  const maxAddPolicyUnits = clean(env.TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI);
  const maxSpendPolicyUnits = clean(env.TINKER_ENCUMBRANCE_MAX_SPEND_WEI);
  const tinkerCapsValid = isUnsignedInteger(maxAddPolicyUnits)
    && isUnsignedInteger(maxSpendPolicyUnits)
    && BigInt(maxAddPolicyUnits) > 0n
    && BigInt(maxSpendPolicyUnits) > 0n
    && BigInt(maxAddPolicyUnits) <= TINKER_MAX_POLICY_UNITS_PER_OPERATION
    && BigInt(maxSpendPolicyUnits) <= BigInt(maxAddPolicyUnits);
  checks.push(check(
    "contract_policy.tinker_operation_caps",
    tinkerCapsValid ? "pass" : "fail",
    tinkerCapsValid
      ? "Tinker add-balance and spend caps are positive, ordered, and within the 10e18 policy-unit per-operation ceiling."
      : "Tinker caps are zero, malformed, out of order, or exceed the 10e18 policy-unit per-operation ceiling.",
    "Choose reviewed positive policy-unit caps with spend no greater than add-balance; these are not ETH or cumulative limits.",
  ));

  const requiredRoleKeys = preMeasuredAuthority
    ? CONSTRUCTOR_STAGE_ROLE_KEYS
    : REQUIRED_ROLE_KEYS;
  const collisions = roleCollisionNames(env, requiredRoleKeys);
  const rolesComplete = requiredRoleKeys.every((name) => isNonzeroAddress(env[name]));
  checks.push(check(
    "roles.pairwise_distinct",
    collisions.length === 0 && rolesComplete
      ? "pass"
      : "fail",
    collisions.length
      ? `Mandatory trust-root roles collide: ${collisions.join(", ")}.`
      : rolesComplete
        ? preMeasuredAuthority
          ? "The two constructor-stage contract roles are pairwise distinct; verifier roles are deferred until measured authority exists."
          : "All five mandatory contract trust-root roles are pairwise distinct."
        : "Pairwise role separation cannot be established until every mandatory role is valid.",
    preMeasuredAuthority
      ? "Provision independently controlled deployment-operator and Compute-developer addresses; bind the three verifier roles only through the reviewed postdeployment ceremony."
      : "Provision five independently controlled addresses; do not reuse the deployment operator or any verifier role.",
  ));

  const accountIsDev = clean(env.FOUNDRY_KEYSTORE_ACCOUNT || "dev") === "dev";
  checks.push(check(
    "keystore.account_policy",
    accountIsDev ? "pass" : "fail",
    accountIsDev
      ? "The configured Foundry account is the required dev alias."
      : "The configured Foundry account is not the required dev alias.",
    "Set FOUNDRY_KEYSTORE_ACCOUNT=dev; never supply a raw private key.",
  ));
  checks.push(check(
    "keystore.dev_present",
    snapshot.probes?.devKeystoreListed === true ? "pass" : "fail",
    snapshot.probes?.devKeystoreListed === true
      ? "The encrypted dev keystore alias is installed; it was not unlocked."
      : "The encrypted dev keystore alias was not found; no unlock was attempted.",
    "Import the operator key into the encrypted dev keystore using the wallet skill.",
  ));
  checks.push(check(
    "keystore.operator_match",
    "warn",
    "The dev signer-to-DEPLOYMENT_OPERATOR match is intentionally not tested because this preflight never unlocks the keystore.",
    "The deployment helper must perform the signer match immediately before an approved broadcast.",
  ));

  const rpcOkay = snapshot.probes?.rpcAttempted === true
    && clean(snapshot.probes?.rpcChainId) === BASE_SEPOLIA_CHAIN_ID;
  checks.push(check(
    "chain.base_sepolia_rpc",
    rpcOkay ? "pass" : "fail",
    rpcOkay
      ? "The configured RPC responded with Base Sepolia chain ID 84532."
      : "The configured RPC was unavailable or did not report Base Sepolia chain ID 84532.",
    "Provide a usable private Base Sepolia RPC endpoint.",
  ));

  const verifyRequested = clean(env.VERIFY).toLowerCase() === "true";
  checks.push(check(
    "contract_policy.verify",
    verifyRequested ? "pass" : "fail",
    verifyRequested
      ? "BaseScan verification is explicitly enabled for the future deployment."
      : "VERIFY=true is not configured for the future deployment.",
    "Set VERIFY=true only for the reviewed deployment invocation; this preflight ignores it.",
  ));
  const broadcastConfigured = clean(env.BROADCAST).toLowerCase() === "true";
  checks.push(check(
    "safety.broadcast_env",
    broadcastConfigured ? "warn" : "pass",
    broadcastConfigured
      ? "BROADCAST=true is configured but is ignored by this preflight; no deployment command is invoked."
      : "Broadcast is disabled in the inspected environment.",
    "Keep BROADCAST=false until the final reviewed deployment invocation.",
  ));

  for (const [id, key, label] of REQUIRED_RUNTIME_CREDENTIALS) {
    const present = clean(env[key]).length > 0;
    const internal = INTERNAL_RUNTIME_CREDENTIAL_KEY_SET.has(key);
    const acceptable = present && (!internal || validInternalRuntimeCredential(env[key]));
    checks.push(check(
      id,
      acceptable ? "pass" : "fail",
      acceptable
        ? `${label} is present and structurally valid; its value is not printed.`
        : present
          ? `${label} is present but does not meet the production secret format; its value is not printed.`
          : `${label} is missing.`,
      `Provision ${key} through an approved secret channel.`,
    ));
  }

  const internalCredentialsWellFormed = INTERNAL_RUNTIME_CREDENTIAL_KEYS.every(
    (key) => validInternalRuntimeCredential(env[key]),
  );
  const aliasesMatch = internalCredentialsWellFormed
    && INTERNAL_RUNTIME_CREDENTIAL_GROUPS
      .filter((group) => group.length > 1)
      .every((group) => group.every((key) => env[key] === env[group[0]]));
  checks.push(check(
    "credential.internal_alias_binding",
    aliasesMatch ? "pass" : "fail",
    aliasesMatch
      ? "Both intentional client/server credential aliases match without exposing either value."
      : "One or more intentional client/server credential aliases is missing, malformed, or split.",
    "Provision each alias pair atomically from one purpose-specific secret value.",
  ));

  const domainValues = INTERNAL_RUNTIME_CREDENTIAL_GROUPS.map((group) => env[group[0]]);
  const domainsSeparated = internalCredentialsWellFormed
    && aliasesMatch
    && new Set(domainValues).size === INTERNAL_RUNTIME_CREDENTIAL_GROUPS.length;
  checks.push(check(
    "credential.internal_domain_separation",
    domainsSeparated ? "pass" : "fail",
    domainsSeparated
      ? "All eight internal credential domains use distinct values except for the two intentional alias pairs."
      : "Internal credentials are missing, malformed, split across an alias pair, or reused across independent trust domains.",
    "Generate eight independent values and reuse only within the two documented alias pairs.",
  ));

  const nekoUser = String(env.NEKO_PASSWORD ?? "");
  const nekoAdmin = String(env.NEKO_PASSWORD_ADMIN ?? "");
  const nekoPolicyOkay = validInternalRuntimeCredential(nekoUser)
    && validInternalRuntimeCredential(nekoAdmin)
    && nekoUser !== "neko"
    && nekoAdmin !== "admin"
    && nekoUser !== nekoAdmin;
  checks.push(check(
    "credential.neko_policy",
    nekoPolicyOkay ? "pass" : "fail",
    nekoPolicyOkay
      ? "Neko user and administrator credentials are strong, non-default, and distinct."
      : "Neko credentials are missing, malformed, default, or identical.",
    "Provision distinct strong Neko user and administrator credentials; never use the upstream defaults.",
  ));
  checks.push(check(
    "auth.phala",
    snapshot.probes?.phalaAuth === true ? "pass" : "fail",
    snapshot.probes?.phalaAuth === true
      ? "Phala CLI authentication is usable via a read-only status probe."
      : "Phala CLI authentication is missing or unusable.",
    "Authenticate with the Phala auth skill, then rerun this preflight.",
  ));
  checks.push(check(
    "auth.github",
    snapshot.probes?.githubAuth === true ? "pass" : "fail",
    snapshot.probes?.githubAuth === true
      ? "GitHub CLI authentication is usable via a read-only status probe."
      : "GitHub CLI authentication is missing or unusable.",
    "Authenticate gh with access to the source repository and package attestations.",
  ));
  checks.push(check(
    "auth.cloudflare",
    snapshot.probes?.cloudflareAuth === true ? "pass" : "fail",
    snapshot.probes?.cloudflareAuth === true
      ? "Wrangler authentication is usable via a read-only identity probe."
      : "Wrangler authentication is missing or unusable.",
    "Authenticate Wrangler for the intended Cloudflare account.",
  ));
  const evidenceLabels = [
    ["releaseCandidate", "release candidate"],
    ["releaseCore", "final release authority core"],
    ["ledger", "fresh-suite deployment ledger"],
    ["artifactEvidence", "artifact deployment evidence"],
    ["arenaEvidence", "Arena deployment evidence"],
    ["anchorWriterEvidence", "anchor-writer QVL evidence"],
  ];
  for (const [key, label] of evidenceLabels) {
    const file = snapshot.files?.[key];
    checks.push(check(
      `evidence.${key.replace(/[A-Z]/g, (match) => `_${match.toLowerCase()}`)}`,
      preMeasuredAuthority ? "warn" : file?.valid === true ? "warn" : "fail",
      preMeasuredAuthority
        ? file?.valid === true
          ? `The ${label} is parseable but cannot substitute for the reviewed ${authorityStage} subject.`
          : `The ${label} is not required as final activation evidence at the ${authorityStage} stage.`
        : file?.valid === true
          ? `The ${label} is only a regular, bounded, parseable input; this is not semantic validation or release authority.`
          : `The ${label} file is missing or invalid.`,
      preMeasuredAuthority
        ? `Generate the ${label} from measured deployment state before release_ceremony.`
        : `Generate and independently review the ${label} for this exact measured authority stage.`,
    ));
  }
  const semanticReceiptValid = semanticLiveActivationReceiptValid(
    snapshot.semanticValidationReceipt,
    {
      deploymentIntentSha256,
      reviewerAuthorityGenesisAcceptanceSha256,
      ceremonyAuthorizationSha256:
        clean(candidateAuthority?.ceremony_authorization_sha256),
      liveActivationAuthoritySha256:
        clean(candidateAuthority?.live_activation_authority_sha256),
      runtimeAuthorityDependencySha256:
        clean(candidateAuthority?.runtime_authority_dependency_sha256),
      releaseSha,
    },
  );
  const semanticEvidenceValidated = liveActivation
    && snapshot.semanticEvidenceValidated === true
    && semanticReceiptValid;
  const semanticFailureReasons = new Set([
    "canonical_semantic_validator_rejected_release",
    "canonical_semantic_validator_receipt_invalid",
    "canonical_semantic_validator_unavailable",
    "canonical_semantic_validator_skipped_network",
    "canonical_semantic_validator_inputs_invalid",
    "canonical_semantic_validator_inputs_changed",
  ]);
  const semanticFailureReason = semanticFailureReasons.has(snapshot.semanticEvidenceReason)
    ? snapshot.semanticEvidenceReason
    : "structural_presence_only_not_release_authority";
  checks.push(check(
    "evidence.semantic_release_authority",
    preMeasuredAuthority || releaseCeremony || semanticEvidenceValidated ? "pass" : "fail",
    preMeasuredAuthority
      ? "Signed live-activation validation is not accepted or required before measured CVM state and post-ceremony authority exist."
      : releaseCeremony
        ? "Post-mutation signed-live-authority validation is intentionally deferred; the ceremony gate cannot claim final on-chain state before it exists."
        : semanticEvidenceValidated
          ? "The exact receipt binds reviewer-genesis acceptance, signed Stage B and Stage C authority, runtime dependency, release inputs, environment, and frontend build lineage."
        : `${semanticFailureReason}: the canonical semantic validator or exact signed-live-authority receipt has not authenticated these inputs.`,
    preMeasuredAuthority
      ? "After CVM deployment, build final authority and a current review before invoking release_ceremony validation."
      : releaseCeremony
        ? "Run the reviewed ceremony, then require a new live_activation preflight and signed-live-authority receipt before Cloudflare deployment."
        : "Provide exact canonical inputs and require the check-only validator receipt with all eight nonzero authority and lineage digests.",
  ));
  const canonicalSevenCvmAuthorityValidated =
    canonicalSevenCvmAuthorityValidationValid(
      snapshot.canonicalSevenCvmAuthorityValidation,
      { authorityStage, releaseSha, deploymentIntentSha256 },
    );
  checks.push(check(
    "evidence.canonical_seven_cvm_authority",
    preMeasuredAuthority || canonicalSevenCvmAuthorityValidated
      ? (preMeasuredAuthority ? "warn" : "pass")
      : "fail",
    preMeasuredAuthority
      ? "Seven-CVM machine evidence is not accepted before CVM deployment; the canonical shared validator must authenticate it for the release ceremony."
      : canonicalSevenCvmAuthorityValidated
        ? authorityStage === "release_ceremony"
          ? "The shared validator authenticated fresh v3 release lineage, exact measurement policies, descriptor/posture authority, durable replay state, and all seven machine proofs."
          : "The shared validator authenticated signed C with exact B/R/L/O/D dependencies and the persisted historical v3 transcript; it did not renew expired machine evidence."
        : "Canonical seven-CVM release authority validation is unavailable or does not match this exact release lineage.",
    preMeasuredAuthority
      ? "Deploy the reviewed topology, then invoke the shared v3 verifier and ceremony authority validator."
      : authorityStage === "release_ceremony"
        ? "Provide the fresh canonical seven-CVM validator result; legacy v1/v2 probes and unpinned quote helpers are never accepted."
        : "Provide the shared historical signed-C dependency validation result; do not remint R/L or rerun expired challenge freshness.",
  ));
  checks.push(check(
    "evidence.anchor_writer_mode",
    preMeasuredAuthority || snapshot.files?.anchorWriterEvidence?.mode === 0o600
      ? (preMeasuredAuthority ? "warn" : "pass")
      : "fail",
    preMeasuredAuthority
      ? "Anchor-writer evidence is postdeployment input and is not accepted before the release ceremony."
      : snapshot.files?.anchorWriterEvidence?.mode === 0o600
        ? "The bounded anchor-writer evidence file is mode 0600."
        : "The bounded anchor-writer evidence file is missing or is not mode 0600.",
    preMeasuredAuthority
      ? "Collect bounded anchor-writer evidence after deployment and restrict it to mode 0600."
      : "Store the canonical bounded artifact as a regular 0600 file.",
  ));

  const imageRelease = snapshot.imageRelease || {
    valid: false, releaseSha: "", sourceRef: "", images: [],
  };
  const imageReleaseMatches = imageRelease.valid === true
    && imageRelease.releaseSha === clean(env.RELEASE_SHA).toLowerCase();
  checks.push(check(
    "evidence.image_release_schema",
    imageReleaseMatches ? "pass" : "fail",
    imageReleaseMatches
      ? "The canonical five-image CI release manifest is exact and matches RELEASE_SHA."
      : "The five-image CI release manifest is invalid or does not match RELEASE_SHA.",
    "Download the exact manifest and provenance bundle from the same clean release-workflow artifact.",
  ));

  const topology = snapshot.topology || { valid: false, domains: {} };
  checks.push(check(
    "evidence.cvm_topology_schema",
    topology.valid === true ? "pass" : "fail",
    topology.valid === true
      ? "The seven-domain CVM topology descriptor is structurally exact and explicitly not deployed."
      : "The seven-domain CVM topology descriptor is missing or invalid.",
    "Render the release compositions from the exact CI image manifest.",
  ));

  const services = snapshot.compose?.services || {};
  const qvlComposes = {
    diligence_qvl_cvm: snapshot.diligenceQvlCompose,
    arena_qvl_cvm: snapshot.arenaQvlCompose,
    anchor_writer_qvl_cvm: snapshot.anchorWriterQvlCompose,
    compute_workload_qvl_cvm: snapshot.computeWorkloadQvlCompose,
    compute_metering_qvl_cvm: snapshot.computeMeteringQvlCompose,
  };
  const qvlServices = Object.fromEntries(
    Object.entries(qvlComposes).map(([domain, compose]) => [domain, compose?.services || {}]),
  );
  const meteringServices = snapshot.meteringCompose?.services || {};
  const allComposesParsed = [
    snapshot.compose,
    ...Object.values(qvlComposes),
    snapshot.meteringCompose,
  ].every((compose) => compose?.valid === true);
  checks.push(check(
    "phala.compose_parse",
    allComposesParsed ? "pass" : "fail",
    allComposesParsed
      ? "All seven generated composes are canonical duplicate-free JSON/YAML and parsed without secret interpolation."
      : "One or more required production CVM composes is missing or could not be parsed.",
    "Render and review all seven production registry-image composes.",
  ));
  const mainTopologyExact = Object.keys(services).length === REQUIRED_PRODUCTION_SERVICES.length
    && REQUIRED_PRODUCTION_SERVICES.every((service) => Object.hasOwn(services, service));
  checks.push(check(
    "phala.main_service_topology",
    mainTopologyExact ? "pass" : "fail",
    mainTopologyExact
      ? "The main descriptor contains exactly the reviewed production service set."
      : "The main descriptor is missing a required service or contains an unreviewed sidecar.",
    "Regenerate the main descriptor; extra sidecars are not release-authorized.",
  ));
  for (const service of REQUIRED_PRODUCTION_SERVICES) {
    const spec = services[service];
    const expectedImage = `${EXPECTED_IMAGE_PREFIX}${EXPECTED_SERVICE_IMAGE_SUFFIX[service]}`;
    const image = clean(spec?.image).toLowerCase();
    const valid = Boolean(spec)
      && IMAGE_PATTERN.test(image)
      && image.startsWith(`${expectedImage}@sha256:`)
      && clean(spec.platform).toLowerCase() === EXPECTED_PLATFORM;
    checks.push(check(
      `phala.service.${service}`,
      valid ? "pass" : "fail",
      valid
        ? `${service} is present with the operator-owned immutable image and linux/amd64 platform.`
        : `${service} is absent or does not use its exact operator-owned linux/amd64 image.`,
      `Render ${service} from the reviewed five-image release artifact.`,
    ));
  }

  function independentDomainValid(domainServices, required, suffix) {
    const expectedImage = `${EXPECTED_IMAGE_PREFIX}${suffix}`;
    return Object.keys(domainServices).length === required.length
      && required.every((service) => {
        const spec = domainServices[service];
        const image = clean(spec?.image).toLowerCase();
        return Boolean(spec)
          && IMAGE_PATTERN.test(image)
          && image.startsWith(`${expectedImage}@sha256:`)
          && clean(spec.platform).toLowerCase() === EXPECTED_PLATFORM;
      });
  }
  for (const [domain, policy] of Object.entries(QVL_DOMAINS)) {
    const valid = independentDomainValid(
      qvlServices[domain],
      REQUIRED_QVL_SERVICES,
      "attestation-qvl",
    );
    checks.push(check(
      `phala.${domain}`,
      valid ? "pass" : "fail",
      valid
        ? `The ${policy.context} QVL descriptor contains only its initializer and exact verifier image.`
        : `The ${policy.context} QVL descriptor is incomplete, mutable, or crosses a trust boundary.`,
      `Render the purpose-separated ${policy.context} QVL CVM from the exact attestation-qvl digest.`,
    ));
  }
  const meteringValid = independentDomainValid(
    meteringServices,
    REQUIRED_METERING_SERVICES,
    "compute-metering",
  );
  checks.push(check(
    "phala.independent_metering",
    meteringValid ? "pass" : "fail",
    meteringValid
      ? "The metering descriptor contains only its initializers and independent metering image."
      : "The independent metering descriptor is incomplete, mutable, or crosses a trust boundary.",
    "Render the independent metering CVM from the exact compute-metering digest.",
  ));

  const composeSecurity = composeSecurityValid("main", snapshot.compose)
    && composeSecurityValid("metering", snapshot.meteringCompose)
    && Object.values(qvlComposes).every((compose) => composeSecurityValid("qvl", compose));
  checks.push(check(
    "phala.compose_security",
    composeSecurity ? "pass" : "fail",
    composeSecurity
      ? "Every service rejects local builds, privilege/host namespaces, unreviewed devices, ports, capabilities, and writable host binds."
      : "A compose contains a local build, privilege/namespace escape, unreviewed port/capability/device, or writable host bind.",
    "Regenerate the canonical composes and review the narrowly documented Neko and metering-init capability exceptions.",
  ));

  const writerToken = "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN";
  const bearerHolders = (key) => Object.entries(services)
    .filter(([, service]) => Object.hasOwn(service.environment || {}, key))
    .map(([name]) => name);
  const writer = services["anchor-writer-evidence"] || {};
  const deal = services["deal-runtime"] || {};
  const compute = services["compute-execution-worker"] || {};
  const evaluatorBindings = Object.entries(services)
    .filter(([, service]) => Object.hasOwn(service.environment || {}, "TINKER_EVALUATOR_MODE"))
    .map(([name, service]) => [name, service.environment.TINKER_EVALUATOR_MODE]);
  const evaluatorBoundaryClosed = evaluatorBindings.length === 1
    && evaluatorBindings[0][0] === "delegate"
    && evaluatorBindings[0][1] === "disabled";
  checks.push(check(
    "phala.confidential_evaluator_boundary",
    evaluatorBoundaryClosed ? "pass" : "fail",
    evaluatorBoundaryClosed
      ? "Production evaluation is disabled until an attested confidential provider preserves the raw-artifact boundary."
      : "The production descriptor selects, omits, or duplicates an evaluator mode that could move seller material outside the CVM.",
    "Regenerate the descriptor with delegate TINKER_EVALUATOR_MODE=disabled; never activate sft or stub in production.",
  ));
  const mainNetworks = snapshot.compose?.document?.networks || {};
  const purposeNetworksIsolated = sameStringSet(serviceNetworks(writer), ["writer-egress"])
    && sameStringSet(serviceNetworks(deal), ["deal-control", "deal-egress"])
    && (serviceNetworks(services.delegate) || []).includes("deal-control")
    && mainNetworks["deal-control"]?.driver === "bridge"
    && mainNetworks["deal-control"]?.internal === true
    && Object.entries(services).every(([name, service]) => {
      const networks = serviceNetworks(service) || [];
      return (name === "anchor-writer-evidence" || !networks.includes("writer-egress"))
        && (["delegate", "deal-runtime"].includes(name) || !networks.includes("deal-control"))
        && (name === "deal-runtime" || !networks.includes("deal-egress"));
    });
  const writerVolumes = JSON.stringify(writer.volumes || []);
  const dealVolumes = JSON.stringify(deal.volumes || []);
  const requiredDealCommandValues = [
    "tinker-deal-runtime",
    "--qvl-url",
    "${TINKER_DILIGENCE_QVL_URL:?Separate Diligence QVL HTTPS /verify URL required}",
    "--allow-compose-hash",
    "${TINKER_DILIGENCE_ALLOWED_COMPOSE_HASH:?Reviewed main CVM compose hash required}",
    "--allow-app-id",
    "${TINKER_DILIGENCE_ALLOWED_APP_ID:?Reviewed main CVM app ID required}",
    "--allow-os-image-hash",
    "${TINKER_DILIGENCE_ALLOWED_OS_IMAGE_HASH:?Reviewed main CVM OS image hash required}",
    "--trusted-attestation-verifier-address",
    "${TINKER_DILIGENCE_QVL_VERIFIER_ADDRESS:?Reviewed Diligence QVL verifier address required}",
    "--attestation-release-policy-hash",
    "${TINKER_DILIGENCE_QVL_RELEASE_POLICY_HASH:?Reviewed Diligence QVL release policy hash required}",
  ];
  const profilesIsolated = sameStringSet(bearerHolders(writerToken), ["anchor-writer-evidence"])
    && sameStringSet(bearerHolders("TINKER_ARENA_WORKER_QVL_AUTH_TOKEN"), ["arena-worker"])
    && sameStringSet(bearerHolders("TINKER_QVL_AUTH_TOKEN"), ["deal-runtime"])
    && sameStringSet(writer.profiles, ["anchor-writer-ceremony"])
    && !writerVolumes.includes("delegate-data")
    && !writerVolumes.includes("arena-worker-sealed")
    && services["arena-policy-init"]?.network_mode === "none"
    && sameStringSet(compute.profiles, ["compute-execution"])
    && compute["x-dnai-capability-status"] === "disabled_provider_contract_unavailable"
    && sameStringSet(deal.profiles, ["deal-settlement"])
    && deal["x-dnai-capability-status"] === "disabled_confidential_evaluator_required"
    && deal.environment?.TINKER_QVL_AUTH_TOKEN
      === "${TINKER_DILIGENCE_QVL_AUTH_TOKEN:?Phala-encrypted Diligence QVL bearer required}"
    && dealVolumes.includes("delegate-data:/data")
    && !dealVolumes.includes("arena-worker-sealed")
    && Array.isArray(deal.command)
    && requiredDealCommandValues.every((value) => deal.command.includes(value))
    && purposeNetworksIsolated;
  checks.push(check(
    "phala.main_release_profiles",
    profilesIsolated ? "pass" : "fail",
    profilesIsolated
      ? "Diligence, Arena, and writer QVL bearers are purpose-separated; Deal and Compute remain profile/release-gated on isolated networks."
      : "A release profile, purpose-specific QVL bearer, required Deal binding, or network boundary is missing or unsafe.",
    "Regenerate the main descriptor; do not manually relax one-shot or provider gates.",
  ));

  const composeImages = [services, ...Object.values(qvlServices), meteringServices]
    .flatMap((domain) => Object.values(domain))
    .map((service) => clean(service.image).toLowerCase())
    .filter((image) => image.includes("@sha256:"));
  const releaseImages = [...(snapshot.releaseImages || [])].map((image) => image.toLowerCase());
  const allImages = [...new Set([...composeImages, ...releaseImages])];
  const requiredImageSetComplete = REQUIRED_IMAGE_SUFFIXES.every(
    (suffix) => allImages.some((image) => imageSuffix(image) === suffix),
  ) && allImages.length === REQUIRED_IMAGE_SUFFIXES.length;
  checks.push(check(
    "image.required_set",
    requiredImageSetComplete ? "pass" : "fail",
    requiredImageSetComplete
      ? "The release evidence contains exactly the five required digest-pinned image subjects."
      : "The release image set is missing a required subject or contains an unreviewed image.",
    "Publish and bind exactly the five canonical images from one clean release SHA.",
  ));
  const ownedImages = allImages.filter((image) => IMAGE_PATTERN.test(image));
  const allImagesOwned = allImages.length > 0 && ownedImages.length === allImages.length;
  checks.push(check(
    "image.operator_namespace",
    allImagesOwned ? "pass" : "fail",
    allImagesOwned
      ? "Every discovered release image is an immutable operator-owned GHCR digest."
      : "One or more discovered images is mutable, malformed, or belongs to a different operator namespace.",
    "Replace historical/operator-external images with clean-CI digests from the required repository.",
  ));

  const actualDomainImages = {
    main_runtime_cvm: [...new Set(Object.values(services).map((service) => clean(service.image).toLowerCase()))],
    ...Object.fromEntries(Object.entries(qvlServices).map(([domain, domainServices]) => [
      domain,
      [...new Set(Object.values(domainServices).map((service) => clean(service.image).toLowerCase()))],
    ])),
    independent_metering_cvm: [...new Set(Object.values(meteringServices).map((service) => clean(service.image).toLowerCase()))],
  };
  const actualDomainServices = {
    main_runtime_cvm: Object.keys(services),
    ...Object.fromEntries(Object.entries(qvlServices).map(([domain, domainServices]) => [
      domain,
      Object.keys(domainServices),
    ])),
    independent_metering_cvm: Object.keys(meteringServices),
  };
  const composeFilesByDomain = {
    main_runtime_cvm: snapshot.files?.mainCompose,
    diligence_qvl_cvm: snapshot.files?.diligenceQvlCompose,
    arena_qvl_cvm: snapshot.files?.arenaQvlCompose,
    anchor_writer_qvl_cvm: snapshot.files?.anchorWriterQvlCompose,
    compute_workload_qvl_cvm: snapshot.files?.computeWorkloadQvlCompose,
    compute_metering_qvl_cvm: snapshot.files?.computeMeteringQvlCompose,
    independent_metering_cvm: snapshot.files?.meteringCompose,
  };
  const composesByDomain = {
    main_runtime_cvm: snapshot.compose,
    ...qvlComposes,
    independent_metering_cvm: snapshot.meteringCompose,
  };
  const topologyBindings = topology.valid === true
    && topology.releaseSha === imageRelease.releaseSha
    && topology.sourceRef === imageRelease.sourceRef
    && topology.generatedAt === imageRelease.generatedAt
    && topology.manifestSha256 === clean(snapshot.files?.imageRelease?.sha256)
    && topology.manifestAttestationSha256
      === clean(snapshot.files?.imageReleaseAttestationBundle?.sha256)
    && Object.entries(composeFilesByDomain).every(([domain, file]) => (
      topology.domains[domain]?.sha256 === clean(file?.sha256)
    ))
    && Object.entries(composesByDomain).every(([domain, compose]) => (
      releaseMetadataValid(compose, domain, imageRelease.releaseSha, imageRelease.sourceRef)
    ))
    && Object.entries(actualDomainImages).every(([domain, images]) => {
      const declared = topology.domains[domain]?.images || [];
      return [...images].sort().join("\0") === [...declared].sort().join("\0");
    })
    && Object.entries(actualDomainServices).every(([domain, serviceNames]) => {
      const declared = topology.domains[domain]?.services || [];
      return [...serviceNames].sort().join("\0") === [...declared].sort().join("\0");
    });
  checks.push(check(
    "evidence.cvm_topology_binding",
    topologyBindings ? "pass" : "fail",
    topologyBindings
      ? "The topology hashes and release metadata bind the exact manifest, its provenance bundle, services, images, and all seven compose descriptors."
      : "The topology does not bind the exact manifest, provenance bundle, service/image topology, metadata, and seven compose files.",
    "Regenerate all release descriptors atomically from the exact image manifest.",
  ));

  const manifestAttestation = snapshot.releaseManifestAttestation || {};
  const releaseManifestProvenance = manifestAttestation.ok === true
    && manifestAttestation.productionVerified === true
    && manifestAttestation.status === "verified_by_pinned_gh_sigstore"
    && manifestAttestation.blockerCode
      === PHALA_RELEASE_MANIFEST_SIGSTORE_VERIFICATION_MISSING
    && manifestAttestation.blockerStatus === "cleared_by_this_receipt"
    && isNonzeroSha256(manifestAttestation.receiptSha256)
    && isNonzeroSha256(manifestAttestation.receiptArtifactFileSha256)
    && manifestAttestation.releaseSha === releaseSha
    && manifestAttestation.releaseManifestSha256
      === `sha256:${clean(snapshot.files?.imageRelease?.sha256)}`
    && manifestAttestation.releaseManifestSigstoreBundleSha256
      === `sha256:${clean(snapshot.files?.imageReleaseAttestationBundle?.sha256)}`
    && snapshot.files?.imageReleaseSigstoreVerificationReceipt?.valid === true
    && manifestAttestation.receiptArtifactFileSha256
      === `sha256:${clean(
        snapshot.files?.imageReleaseSigstoreVerificationReceipt?.sha256,
      )}`
    && snapshot.files?.imageReleaseAttestationBundle?.valid === true;
  checks.push(check(
    "image.release_manifest_provenance",
    releaseManifestProvenance ? "pass" : "fail",
    releaseManifestProvenance
      ? "The pinned gh executable freshly verified the exact manifest/bundle identity, and the canonical production receipt matches the stable persisted bytes."
      : "The canonical release manifest lacks a fresh production-branded pinned-gh Sigstore receipt bound to the exact stable manifest and bundle bytes.",
    "Verify the exact CI manifest and bundle with the pinned Sigstore verifier, persist its canonical production receipt, and rerun online preflight.",
  ));

  const manifestBindsImages = imageReleaseMatches
    && [...imageRelease.images].sort().join("\0") === [...allImages].sort().join("\0");
  checks.push(check(
    "evidence.image_release_binding",
    manifestBindsImages ? "pass" : "fail",
    manifestBindsImages
      ? "Every compose image is bound by the exact canonical CI image manifest."
      : "One or more compose images is absent from or differs from the canonical CI manifest.",
    "Regenerate the seven composes from the exact five-image release manifest.",
  ));
  const expectedAttestations = ownedImages.length * 2;
  const attestationResults = snapshot.attestations || [];
  const verifiedAttestations = attestationResults.filter((result) => result.ok === true).length;
  const attestationsComplete = expectedAttestations > 0
    && attestationResults.length === expectedAttestations
    && verifiedAttestations === expectedAttestations
    && allImagesOwned;
  checks.push(check(
    "image.provenance_sbom",
    attestationsComplete ? "pass" : "fail",
    attestationsComplete
      ? "GitHub verified SLSA provenance and SPDX SBOM attestations for every exact release image and source SHA."
      : "SLSA provenance and SPDX SBOM verification is incomplete or failed for the exact release image set.",
    "Publish in clean GitHub CI and verify both attestations for every digest before Phala deployment.",
  ));

  const counts = { pass: 0, warn: 0, fail: 0 };
  for (const item of checks) counts[item.status] += 1;
  const actions = [...new Set(
    checks.filter((item) => item.status !== "pass" && item.action).map((item) => item.action),
  )].slice(0, 20);
  return {
    schema: PREFLIGHT_SCHEMA,
    verdict: counts.fail === 0 ? "READY" : "BLOCKED",
    summary: counts,
    invariants: {
      secret_values_printed: false,
      keystore_unlocked: false,
      broadcast_attempted: false,
      deployment_attempted: false,
      remote_state_mutated: false,
    },
    checks,
    next_actions: actions,
  };
}

export function sensitiveValues(env) {
  return Object.entries(env || {})
    .filter(([name, value]) => SECRET_NAME_PATTERN.test(name) && clean(value).length >= 4)
    .map(([, value]) => clean(value));
}

export function assertReportContainsNoSensitiveValues(report, env) {
  const serialized = JSON.stringify(report);
  for (const value of sensitiveValues(env)) {
    if (serialized.includes(value)) {
      throw new Error("preflight report safety invariant failed: a sensitive value reached output");
    }
  }
}

export function formatHumanReport(report) {
  const lines = [
    `activation_preflight_schema=${report.schema}`,
    `verdict=${report.verdict}`,
    `summary=pass:${report.summary.pass},warn:${report.summary.warn},fail:${report.summary.fail}`,
    "safety=read-only,no-keystore-unlock,no-broadcast,no-deploy,no-remote-mutation,no-secret-values",
    "",
  ];
  for (const item of report.checks) {
    lines.push(`[${item.status.toUpperCase()}] ${item.id} - ${item.message}`);
  }
  if (report.next_actions.length) {
    lines.push("", "next_actions:");
    report.next_actions.forEach((action, index) => lines.push(`${index + 1}. ${action}`));
  }
  return `${lines.join("\n")}\n`;
}

export function defaultComposePath(rootDir) {
  return path.join(rootDir, ".release", "dnai-main-runtime.phala.yaml");
}

export function defaultDiligenceQvlComposePath(rootDir) {
  return path.join(rootDir, ".release", "dnai-diligence-qvl.phala.yaml");
}

export function defaultArenaQvlComposePath(rootDir) {
  return path.join(rootDir, ".release", "dnai-arena-qvl.phala.yaml");
}

export function defaultAnchorWriterQvlComposePath(rootDir) {
  return path.join(rootDir, ".release", "dnai-anchor-writer-qvl.phala.yaml");
}

export function defaultComputeWorkloadQvlComposePath(rootDir) {
  return path.join(rootDir, ".release", "dnai-compute-workload-qvl.phala.yaml");
}

export function defaultComputeMeteringQvlComposePath(rootDir) {
  return path.join(rootDir, ".release", "dnai-compute-metering-qvl.phala.yaml");
}

export function defaultMeteringComposePath(rootDir) {
  return path.join(rootDir, ".release", "dnai-independent-metering.phala.yaml");
}

export function defaultImageReleasePath(rootDir) {
  return path.join(rootDir, ".release", "dnai-tee-image-release.json");
}

export function defaultImageReleaseAttestationBundlePath(rootDir) {
  return path.join(rootDir, ".release", "dnai-tee-image-release.bundle.json");
}

export function defaultImageReleaseSigstoreVerificationReceiptPath(rootDir) {
  return path.join(
    rootDir,
    ".release",
    "dnai-tee-image-release-manifest-sigstore-verification.json",
  );
}

export function defaultTopologyPath(rootDir) {
  return path.join(rootDir, ".release", "dnai-cvm-topology.json");
}
