import { createHash } from "node:crypto";

import {
  PHALA_PRODUCTION_EXECUTION_POLICY,
} from "./phala-production-execution-policy.mjs";

export const CVM_LAUNCH_INTENT_CORE_SCHEMA = "dnai.cvm-launch-intent-core.v3";
export const CVM_LAUNCH_INTENT_RECEIPT_SCHEMA =
  "dnai.cvm-launch-intent-validation-receipt.v3";
export const CVM_LAUNCH_INTENT_DOMAIN =
  "dnai-wikigen/cvm-launch-intent-core/v3\0";
export const CVM_LAUNCH_ENVIRONMENT_KEYS_DOMAIN =
  "dnai-wikigen/cvm-launch-intent-environment-keys/v1\0";
export const CVM_LAUNCH_OS_IMAGE_CATALOG_ENTRY_DOMAIN =
  "dnai-wikigen/phala-os-image-catalog-entry/v1\0";
export const FRESH_CONTRACT_DEPLOYMENT_RECEIPT_V3_SCHEMA =
  "dnai.fresh-contract-deployment-receipt.v3";
export const FRESH_CONTRACT_DEPLOYMENT_RECEIPT_V3_DOMAIN =
  "dnai-wikigen/fresh-contract-deployment-receipt/v3\0";
export const FRESH_CONTRACT_DEPLOYMENT_RECEIPT_SCHEMA =
  "dnai.fresh-contract-deployment-receipt.v4";
export const FRESH_CONTRACT_DEPLOYMENT_RECEIPT_DOMAIN =
  "dnai-wikigen/fresh-contract-deployment-receipt/v4\0";
export const FRESH_CONTRACT_CREATION_INPUT_PROOF =
  "mined_transaction_input_equals_release_snapshot_creation_input_all_contracts";
export const FRESH_CONTRACT_BROADCAST_PROOF =
  "exact_ordered_13_transaction_receipts_with_consecutive_nonces";
export const FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF =
  "primary_and_secondary_rpc_exact_getter_match_at_deployment_block";
export const CVM_TOPOLOGY_SCHEMA = "dnai.cvm-topology.v6";
export const BASE_SEPOLIA_CHAIN_ID = 84_532;
export const BASE_SEPOLIA_NAME = "base-sepolia";
// This matches the shared renewable-review subject reader. A launch artifact
// that validates here must never become unreviewable at the next gate.
export const MAX_CVM_LAUNCH_INTENT_BYTES = 98_304;

export const CVM_LAUNCH_TRUTH_STATUS =
  "value_free_pre_phala_launch_gate_specification_not_runtime_value_authority_cvm_deployment_tdx_quote_or_runtime_measurement";
export const CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA =
  "dnai.cvm-public-environment-value-projector.v1";
export const CVM_PUBLIC_ENVIRONMENT_VALUE_AUTHORITY_TRUTH_STATUS =
  "value_free_gate_specification_not_runtime_value_authority";

const ENVIRONMENT_KEY = /^[A-Z][A-Z0-9_]{0,127}$/;

export const CVM_LAUNCH_DOMAINS = Object.freeze([
  "main_runtime_cvm",
  "diligence_qvl_cvm",
  "arena_qvl_cvm",
  "anchor_writer_qvl_cvm",
  "compute_workload_qvl_cvm",
  "compute_metering_qvl_cvm",
  "independent_metering_cvm",
]);

export const CVM_LAUNCH_SECRET_PHASES = Object.freeze([
  "bootstrap_provision",
  "post_measurement_policy_bootstrap",
  "final_authority_runtime",
  "anchor_writer_ceremony",
]);

// COMPOSE_PROFILES is replacement state, not an additive toggle. Every
// production transition therefore owns the complete, sorted profile set.
// Account genesis is one exact two-profile attempt followed by permanent
// retirement to the empty set. The existing Arena/Compute set remains the
// non-live post-measurement boundary. Deal settlement and the bounded review
// operations worker may join that complete long-running set only through the
// separate post-ceremony live gate.
export const CVM_MAIN_DISABLED_PROFILE_NAMES = Object.freeze([]);
export const CVM_MAIN_DISABLED_COMPOSE_PROFILES_VALUE = "";
export const CVM_MAIN_DISABLED_PROFILE_POLICY = Object.freeze({
  profile_names: CVM_MAIN_DISABLED_PROFILE_NAMES,
  compose_profiles_value: CVM_MAIN_DISABLED_COMPOSE_PROFILES_VALUE,
});
export const CVM_MAIN_ACCOUNT_GENESIS_PROFILE_NAMES = Object.freeze([
  "mailbox-genesis",
  "tinker-account-genesis",
]);
export const CVM_MAIN_ACCOUNT_GENESIS_COMPOSE_PROFILES_VALUE =
  CVM_MAIN_ACCOUNT_GENESIS_PROFILE_NAMES.join(",");
export const CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY = Object.freeze({
  profile_names: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_NAMES,
  compose_profiles_value:
    CVM_MAIN_ACCOUNT_GENESIS_COMPOSE_PROFILES_VALUE,
});
export const CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES = Object.freeze([
  "arena-runtime",
  "compute-execution",
]);
export const CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE =
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES.join(",");
export const CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY = Object.freeze({
  profile_names: CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
  compose_profiles_value:
    CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
});
export const CVM_MAIN_LIVE_DEAL_PROFILE_NAMES = Object.freeze([
  "arena-runtime",
  "collaboration-execution",
  "compute-execution",
  "deal-settlement",
  "review-operations",
]);
export const CVM_MAIN_LIVE_DEAL_COMPOSE_PROFILES_VALUE =
  CVM_MAIN_LIVE_DEAL_PROFILE_NAMES.join(",");
export const CVM_MAIN_LIVE_DEAL_PROFILE_POLICY = Object.freeze({
  profile_names: CVM_MAIN_LIVE_DEAL_PROFILE_NAMES,
  compose_profiles_value: CVM_MAIN_LIVE_DEAL_COMPOSE_PROFILES_VALUE,
});
export const CVM_MAIN_PRODUCTION_PROFILE_TRANSITIONS = Object.freeze([
  Object.freeze({
    sequence: 1,
    name: "account_genesis_start",
    from: CVM_MAIN_DISABLED_PROFILE_POLICY,
    to: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
    one_shot: true,
    live_traffic_after_transition: false,
  }),
  Object.freeze({
    sequence: 2,
    name: "account_genesis_retire",
    from: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
    to: CVM_MAIN_DISABLED_PROFILE_POLICY,
    one_shot: true,
    live_traffic_after_transition: false,
  }),
  Object.freeze({
    sequence: 3,
    name: "nonlive_runtime_start",
    from: CVM_MAIN_DISABLED_PROFILE_POLICY,
    to: CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
    one_shot: false,
    live_traffic_after_transition: false,
  }),
  Object.freeze({
    sequence: 4,
    name: "deal_runtime_start",
    from: CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
    to: CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
    one_shot: false,
    // Starting the service is not itself a live-routing authorization. The
    // independent post-restart TDX and service-presence verifier must still
    // issue the terminal traffic gate.
    live_traffic_after_transition: false,
  }),
]);

export const CVM_LAUNCH_DESCRIPTOR_FILES = Object.freeze({
  main_runtime_cvm: "dnai-main-runtime.phala.yaml",
  diligence_qvl_cvm: "dnai-diligence-qvl.phala.yaml",
  arena_qvl_cvm: "dnai-arena-qvl.phala.yaml",
  anchor_writer_qvl_cvm: "dnai-anchor-writer-qvl.phala.yaml",
  compute_workload_qvl_cvm: "dnai-compute-workload-qvl.phala.yaml",
  compute_metering_qvl_cvm: "dnai-compute-metering-qvl.phala.yaml",
  independent_metering_cvm: "dnai-independent-metering.phala.yaml",
});

export const PHALA_CVM_APP_COMPOSE_NAMES = Object.freeze({
  main_runtime_cvm: "dnai-main-runtime",
  diligence_qvl_cvm: "dnai-diligence-attestation-qvl",
  arena_qvl_cvm: "dnai-arena-attestation-qvl",
  anchor_writer_qvl_cvm: "dnai-anchor-writer-attestation-qvl",
  compute_workload_qvl_cvm: "dnai-compute-workload-attestation-qvl",
  compute_metering_qvl_cvm: "dnai-compute-metering-attestation-qvl",
  independent_metering_cvm: "dnai-independent-compute-metering",
});

// Reviewed from the authenticated Phala Cloud production image catalog on
// 2026-07-21. The timestamp is deliberately not part of launch authority: the
// fresh provisioning helper must re-query the authenticated catalog and find
// this exact entry before it prepares or commits any CVM. The selector passed
// to `provisionCvm` is the catalog `name`, never the slug and never an inferred
// "latest" or development-image preference.
export const PHALA_OS_IMAGE_CATALOG_ENTRY = Object.freeze({
  name: "dstack-0.5.10",
  slug: "dstack-0.5.10-4c9bd024",
  version: "0.5.10",
  os_image_hash: "4c9bd0249cf8a1f79f7b558867b0791d628d7a89dcba84a963338fc5539255fc",
  is_dev: false,
  requires_gpu: false,
});

export const PHALA_CONTROL_PLANE_AUTHORITY = Object.freeze({
  api_origin: "https://cloud-api.phala.network/api/v1",
  api_version: "2026-01-21",
  redirects_allowed: false,
  origin_drift_allowed: false,
  phala_cloud_api_prefix_environment_override_allowed: false,
  default_discovery_allowed: false,
  adapter_status: "required_not_implemented",
});

export const PHALA_WORKSPACE_ACCOUNT_TARGET_AUTHORITY = Object.freeze({
  status: "required_external_reviewed_target_artifact_not_present",
  target_artifact_schema: "dnai.phala-workspace-account-target.v1",
  workspace_id_present: false,
  account_id_present: false,
  target_artifact_digest_present: false,
  required_checkpoint: "before_any_phala_sdk_call",
});

export const PHALA_SDK_DEBUG_SECRET_LOGGING_POLICY = Object.freeze({
  status: "required_not_implemented",
  forbidden_debug_selector: "phala::api-client",
  enforcement_checkpoint: "before_dynamic_import_of_phala_sdk",
  required_debug_environment_state: "absent_or_empty",
  stdout_secret_bytes_allowed: false,
  stderr_secret_bytes_allowed: false,
  required_proof: "zero_secret_bytes_in_captured_stdout_and_stderr",
});

export const PHALA_DSTACK_COMPOSE_HASH_AUTHORITY = Object.freeze({
  status:
    "local_expected_hash_projection_staging_server_semantics_evidence_pending_non_executable",
  package_name: "@phala/dstack-sdk",
  package_version: "0.5.8",
  import_path: "@phala/dstack-sdk/get-compose-hash",
  export_name: "getComposeHash",
  normalize: false,
  algorithm:
    "recursive_lexical_key_sort_compact_json_utf8_sha256_bare_lowercase_hex",
  output_pattern: "^[0-9a-f]{64}$",
  descriptor_bytes_semantics: "exact_stable_read_raw_descriptor_bytes",
  prepare_response_policy:
    "all_seven_prepare_compose_hashes_must_equal_their_exact_local_expected_hash_before_first_commit",
  staging_server_semantics_evidence_status: "required_not_implemented",
});

export const PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY = Object.freeze({
  status: "reviewed_transform_and_staging_capture_required_not_present",
  package: Object.freeze({
    name: "@phala/cloud",
    version: "0.2.10",
    registry_origin: "https://registry.npmjs.org",
    npm_dist_integrity_sha512:
      "sha512-eQXJxbBlJ8xA4e+MmB3AZd9jgdbO3tFh+qu7KL6CS5Ta64LNKlrV3vdke3oUvB22xbc/qqKQ6dIkJx5pTdY7gA==",
    installed_integrity_source:
      "stable_nofollow_package_manifest_and_exact_dist_index_mjs_bytes",
    installed_manifest_sha256: null,
    installed_esm_module_sha256: null,
  }),
  provision_transform: Object.freeze({
    entrypoint: "provisionCvm",
    parse_step: "ProvisionCvmRequestSchema.parse",
    function: "handleGatewayCompatibility",
    rule:
      "when_compose_file_gateway_enabled_and_tproxy_enabled_are_both_boolean_delete_compose_file_tproxy_enabled",
    additional_transform_allowed: false,
  }),
  digest: Object.freeze({
    schema: "dnai.phala-sdk-json-body-semantic-digest.v1",
    domain: "dnai-wikigen/phala-sdk-json-body-semantic/v1\0",
    algorithm:
      "sha256_domain_then_recursive_lexical_key_sort_compact_json_utf8",
    unit: "parsed_json_body_semantics_excluding_headers_and_http_framing",
  }),
  required_evidence: Object.freeze([
    "pre_transform_request_sha256",
    "expected_post_transform_body_sha256",
    "captured_post_transform_body_sha256",
    "prepare_server_compose_hash",
    "authenticated_staging_receipt_sha256",
  ]),
});

export const PHALA_DSTACK_APP_COMPOSE_HASH_INPUT_KEYS = Object.freeze([
  "name",
  "manifest_version",
  "runner",
  "docker_compose_file",
  "kms_enabled",
  "gateway_enabled",
  "secure_time",
  "storage_fs",
  "tproxy_enabled",
  "public_logs",
  "public_sysinfo",
  "public_tcbinfo",
  "allowed_envs",
]);

export const PHALA_CVM_RESOURCE_TARGETS = Object.freeze(Object.fromEntries(
  CVM_LAUNCH_DOMAINS.map((domain) => [domain, Object.freeze({
    authority_status: "reviewed_target_pending_authenticated_catalog_and_quota_probe",
    instance_type: domain === "main_runtime_cvm" ? "tdx.large" : "tdx.small",
    disk_size: domain === "main_runtime_cvm" ? 40 : 20,
    placement: Object.freeze({
      selection_mode: "automatic_best_match",
      node_id: null,
      region: null,
    }),
  })]),
));

export const PHALA_PROVISION_REQUEST_AUTHORITY = Object.freeze({
  status: "dynamic_authorities_pending_non_executable",
  request_defaults_allowed: false,
  request_extra_fields_allowed: false,
  listed: false,
  image: PHALA_OS_IMAGE_CATALOG_ENTRY.name,
  kms_id: null,
  key_provider_mode: "kms",
  compose_file_source: "descriptor.app_compose_candidate",
  name_source: "descriptor.app_compose_candidate.name",
  resource_source: "descriptor.launch_settings.cvm_resource_target",
  env_keys_source: "descriptor.exact_allowed_environment_keys",
  unresolved_fields: Object.freeze([
    "kms_id",
    "nonce",
    "app_id",
    "exact_request_sha256",
  ]),
  candidates: Object.freeze(Object.fromEntries(
    CVM_LAUNCH_DOMAINS.map((domain) => [domain, Object.freeze({
      nonce: null,
      app_id: null,
      exact_request_sha256: null,
    })]),
  )),
});

const QVL_NUMERIC_KEYS = Object.freeze([
  "QVL_CHALLENGE_CAPACITY",
  "QVL_CHALLENGE_TTL_SECONDS",
  "QVL_MAX_CONCURRENCY",
  "QVL_RATE_CAPACITY",
  "QVL_RATE_REFILL_PER_SECOND",
  "QVL_REQUEST_BODY_TIMEOUT_SECONDS",
  "QVL_VERIFICATION_TIMEOUT_SECONDS",
]);

const MAIN_STATIC_KEYS = Object.freeze([
  "EMAIL_ORACLE_AUTH_ADDRESS",
  "EMAIL_ORACLE_AUTH_RUNTIME_CODE_HASH",
  "TINKER_ARENA_PROVISION_EVALUATOR_SHA256",
  "TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256",
  "TINKER_ARENA_WORKER_IMAGE_DIGEST",
  "TINKER_ARENA_WORKER_RELEASE_SHA",
  "TINKER_CHAIN_CONTRACT_ADDRESS",
  "TINKER_CHAIN_START_BLOCK",
  "TINKER_COMPUTE_VAULT_ADDRESS",
  "TINKER_COMPUTE_VAULT_RUNTIME_CODE_HASH",
  "TINKER_COMPUTE_WORKLOAD_CHAIN_ID",
  "TINKER_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256",
  "TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE",
  "TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
  "TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256",
  "TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256",
  "TINKER_COMPUTE_WORKLOAD_QVL_MAX_VERDICT_AGE_SECONDS",
  "TINKER_COMPUTE_WORKLOAD_QVL_REVOKED_QUOTE_HASHES_JSON",
  "TINKER_CORS_ALLOWED_ORIGINS",
  "TINKER_DILIGENCE_CHAIN_ID",
  "TINKER_DILIGENCE_EVALUATOR_RELEASE_B64",
  "TINKER_DILIGENCE_EVALUATOR_POLICY_SET_ROOT",
  "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_PATH",
  "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_SHA256",
  "TINKER_DILIGENCE_ROOM_ADDRESS",
  "TINKER_EXECUTION_POLICY_ANCHOR_ADDRESS",
  "TINKER_EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH",
  "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT",
  "TINKER_EXECUTION_POLICY_APPROVAL_DOMAIN",
  "TINKER_EXECUTION_POLICY_APPROVED_SIGNERS",
  "TINKER_EXECUTION_POLICY_APPROVER_ROOT_HASH",
  "TINKER_FUNDING_PREFLIGHT_ALLOWED_HOSTS",
  "TINKER_RELEASE_REVIEWER_AUTHORITY_ACTIVE_REVIEWERS_SHA256",
  "TINKER_RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_EPOCH",
  "TINKER_RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SHA256",
  "TINKER_RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256",
  "TINKER_REVIEW_AUTHORITY_POLICY_SHA256",
  "TINKER_ROYALTY_QVL_MAX_VERDICT_AGE_SECONDS",
  "TINKER_ROYALTY_QVL_REVOKED_QUOTE_HASHES_JSON",
  "TINKER_WALLET_AUTH_CHAIN_ID",
  "TINKER_WALLET_AUTH_DOMAIN",
  "TINKER_WALLET_AUTH_URI",
]);

const MAIN_PROVISIONING_KEYS = Object.freeze([
  "EMAIL_ORACLE_CONSUMER_APP_ID",
  "EMAIL_ORACLE_CONSUMER_COMPOSE_HASH",
  "TINKER_ARENA_WORKER_APP_ID",
  "TINKER_ARENA_WORKER_COMPOSE_HASH",
  "TINKER_ARENA_WORKER_OS_IMAGE_HASH",
  "TINKER_COMPUTE_VAULT_COMPOSE_HASH",
  "TINKER_COMPUTE_WORKLOAD_CVM_ID",
  "TINKER_DILIGENCE_ALLOWED_APP_ID",
  "TINKER_DILIGENCE_ALLOWED_COMPOSE_HASH",
  "TINKER_DILIGENCE_ALLOWED_OS_IMAGE_HASH",
]);

const MAIN_DEFERRED_KEYS = Object.freeze([
  "ORACLE_REVIEW_NOTIFICATIONS_ENABLED",
  "ORACLE_REVIEW_NOTIFICATION_RECIPIENTS_SHA256",
  "ORACLE_REVIEW_NOTIFICATION_SMTP_HOST",
  "TINKER_ARENA_REGISTRY_ADDRESS",
  "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON",
  "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
  "TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH",
  "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
  "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
  "TINKER_ARENA_WORKER_QVL_RELEASE_POLICY_HASH",
  "TINKER_ARENA_WORKER_QVL_VERDICT_URL",
  "TINKER_COMPUTE_METERING_URL",
  "TINKER_COMPUTE_METERING_POLICY_SET_HASH",
  "TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
  "TINKER_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH",
  "TINKER_COMPUTE_WORKLOAD_QVL_URL",
  "TINKER_COMPUTE_WORKLOAD_QVL_VERIFIER_ADDRESS",
  "TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
  "TINKER_COLLABORATION_ENABLED",
  "TINKER_COLLABORATION_EXECUTION_ENABLED",
  "TINKER_COLLABORATION_EXECUTION_RELEASE_GIT_SHA",
  "TINKER_COLLABORATION_EXECUTION_RELEASE_VERIFICATION_SHA256",
  "TINKER_COLLABORATION_EXECUTION_ROYALTY_RESERVATION_SAFETY_SECONDS",
  "TINKER_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED",
  "TINKER_CUSTOMER_AUTHORITY_SHA256",
  "TINKER_CUSTOMER_ENABLED",
  "TINKER_DILIGENCE_QVL_RELEASE_POLICY_HASH",
  "TINKER_DILIGENCE_QVL_URL",
  "TINKER_DILIGENCE_QVL_VERIFIER_ADDRESS",
  "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_ADDRESS",
  "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_RELEASE_POLICY_HASH",
  "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_URL",
  "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_VERIFIER_ADDRESS",
  "TINKER_ROYALTY_ANCHOR_WRITER_RELEASE_COMMITMENT",
  "TINKER_ROYALTY_AUTHORITY_NONCE",
  "TINKER_ROYALTY_DISTRIBUTOR_ADDRESS",
  "TINKER_ROYALTY_DISTRIBUTOR_RUNTIME_CODE_HASH",
  "TINKER_ROYALTY_EXECUTION_POLICY_ANCHOR",
  "TINKER_ROYALTY_MEASUREMENT_POLICY_SHA256",
  "TINKER_ROYALTY_OWNER_ADDRESS",
  "TINKER_ROYALTY_QVL_POLICY_COMMITMENT",
  "TINKER_ROYALTY_QVL_RELEASE_POLICY_HASH",
  "TINKER_ROYALTY_QVL_SIGNER_KEY_ID",
  "TINKER_ROYALTY_QVL_VERDICT_VERIFIER_ADDRESS",
  "TINKER_ROYALTY_QVL_VERIFIER",
  "TINKER_ROYALTY_RELEASE_POLICY_COMMITMENT",
  "TINKER_ROYALTY_SETTLEMENT_QVL_URL",
  "TINKER_ROYALTY_SETTLEMENT_VERIFIER",
  "TINKER_ACCOUNT_GENESIS_AUTHORIZATION_SHA256",
  "TINKER_ACCOUNT_GENESIS_MAIN_QVL_VERDICT_SHA256",
  "TINKER_ACCOUNT_GENESIS_MEASUREMENT_POLICY_SHA256",
]);

const MAIN_SECRET_KEYS_BY_PHASE = Object.freeze({
  bootstrap_provision: Object.freeze([
    "BASE_SEPOLIA_RPC_URL",
    "BASE_SEPOLIA_RPC_URL_SECONDARY",
    "NEKO_PASSWORD",
    "NEKO_PASSWORD_ADMIN",
    "TINKER_RELEASE_REVIEWER_AUTHORITY_ACTIVE_REVIEWERS_JSON",
    "TINKER_REVIEW_AUTHORITY_POLICY_JSON",
    "TINKER_WALLET_AUTH_RPC_URL",
    "TINKER_WALLET_AUTH_RPC_URL_SECONDARY",
  ]),
  post_measurement_policy_bootstrap: Object.freeze([
    "TINKER_ACCOUNT_BINDING_SHARE_ONE",
    "TINKER_ACCOUNT_BINDING_SHARE_TWO",
  ]),
  final_authority_runtime: Object.freeze([
    "ORACLE_REVIEW_NOTIFICATION_RECIPIENTS_JSON",
    "TINKER_ARENA_REGISTRY_RPC_URL",
    "TINKER_ARENA_PROVISION_AUTH_KEY_B64",
    "TINKER_ARENA_PROVISION_AUTH_TAG",
    "TINKER_ARENA_PROVISION_EVALUATOR_B64",
    "TINKER_ARENA_PROVISION_RELEASE_B64",
    "TINKER_ARENA_WORKER_QVL_AUTH_TOKEN",
    "TINKER_CHAIN_RPC_URL",
    "TINKER_COMPUTE_CHAIN_RPC_URL",
    "TINKER_COMPUTE_METERING_AUTH_TOKEN",
    "TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN",
    "TINKER_CUSTOMER_AUTHORITY_B64",
    "TINKER_DILIGENCE_QVL_AUTH_TOKEN",
    "TINKER_EXECUTION_POLICY_ANCHOR_RPC_URL",
    "TINKER_ROYALTY_SETTLEMENT_QVL_AUTH_TOKEN",
  ]),
  anchor_writer_ceremony: Object.freeze([
    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN",
  ]),
});

// These names occur only in `${KEY:-descriptor-default}` expressions. They are
// part of the reviewed public key-name surface but are deliberately excluded
// from Phala's encrypted allowed-env set, so an operator cannot override the
// fail-closed descriptor defaults during the launch ceremony.
const MAIN_DESCRIPTOR_DEFAULTED_KEYS = Object.freeze([
  "ORACLE_DOMAIN",
  "ORACLE_USE_BROWSER_FALLBACK",
  "TINKER_ARENA_CANDIDATE_INGRESS_KEY_PATH",
  "TINKER_ARENA_CANDIDATE_INGRESS_MAX_ENVELOPES",
  "TINKER_ARENA_CANDIDATE_INGRESS_STORE_PATH",
  "TINKER_ARENA_REGISTRY_MAX_BLOCK_AGE_SECONDS",
  "TINKER_ARENA_REGISTRY_MAX_FUTURE_BLOCK_SKEW_SECONDS",
  "TINKER_ARENA_STORE_PATH",
  "TINKER_ARENA_WALLET_AUTH_CHALLENGE_TTL_SECONDS",
  "TINKER_ARENA_WALLET_AUTH_KEY_PATH",
  "TINKER_ARENA_WALLET_AUTH_MAX_PENDING_CHALLENGES",
  "TINKER_ARENA_WALLET_AUTH_TOKEN_TTL_SECONDS",
  "TINKER_ARENA_WORKER_HEARTBEAT_KEY_PATH",
  "TINKER_ARENA_WORKER_HEARTBEAT_TTL_SECONDS",
  "TINKER_ARENA_WORKER_POLL_INTERVAL_SECONDS",
  "TINKER_BOOTSTRAP_ORACLE_POLL_INTERVAL",
  "TINKER_BOOTSTRAP_ORACLE_TIMEOUT",
  "TINKER_BROWSER_SESSION_KEY_PATH",
  "TINKER_CHAIN_CONFIRMATIONS",
  "TINKER_CHAIN_POLL_INTERVAL",
  "TINKER_CHAIN_RESULT_AUTHORIZATION_TTL_SECONDS",
  "TINKER_COMPUTE_CREDENTIAL_KEY_PATH",
  "TINKER_COMPUTE_DISPATCH_STORE_INTEGRITY_KEY_PATH",
  "TINKER_COMPUTE_DISPATCH_STORE_PATH",
  "TINKER_COMPUTE_EXECUTION_CONFIRMATIONS",
  "TINKER_COMPUTE_EXECUTION_MAX_BLOCK_AGE_SECONDS",
  "TINKER_COMPUTE_EXECUTION_MAX_FUTURE_BLOCK_SKEW_SECONDS",
  "TINKER_COMPUTE_EXECUTION_POLL_INTERVAL_SECONDS",
  "TINKER_COMPUTE_EXECUTION_SIGNER_KEY_PATH",
  "TINKER_COMPUTE_STORE_INTEGRITY_KEY_PATH",
  "TINKER_COMPUTE_STORE_PATH",
  "TINKER_COMPUTE_WALLET_AUTH_KEY_PATH",
  "TINKER_DSTACK_KEY_PATH",
  "TINKER_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS",
  "TINKER_EXECUTION_POLICY_ANCHOR_CONFIRMATION_WAIT_SECONDS",
  "TINKER_EXECUTION_POLICY_ANCHOR_MAX_BLOCK_AGE_SECONDS",
  "TINKER_EXECUTION_POLICY_ANCHOR_MAX_FUTURE_BLOCK_SKEW_SECONDS",
  "TINKER_EXECUTION_POLICY_ANCHOR_POLL_INTERVAL_SECONDS",
  "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH",
  "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_MAX_VERDICT_AGE_SECONDS",
  "TINKER_EXECUTION_POLICY_STORE_INTEGRITY_KEY_PATH",
  "TINKER_EXECUTION_POLICY_STORE_PATH",
  "TINKER_FIRST_NAME",
  "TINKER_FUNDING_MODE",
  "TINKER_FUNDING_RECEIPT_KEY_PATH",
  "TINKER_LAST_NAME",
  "TINKER_MAX_ADD_BALANCE_USD",
  "TINKER_MIN_ADD_BALANCE_USD",
  "TINKER_ORACLE_AUTH_KEY_PATH",
  "TINKER_RUNTIME_AUTH_KEY_PATH",
  "TINKER_RUNTIME_AUTH_TOKEN",
  "TINKER_REVIEW_AUTHORITY_CHALLENGE_TTL_SECONDS",
  "TINKER_REVIEW_AUTHORITY_MAX_PENDING_CHALLENGES",
  "TINKER_REVIEW_OPERATIONS_MAXIMUM_NOTIFICATIONS_PER_TICK",
  "TINKER_REVIEW_OPERATIONS_MAXIMUM_QUEUE_PAGES",
  "TINKER_REVIEW_OPERATIONS_POLL_INTERVAL_SECONDS",
  "TINKER_REVIEW_OPERATIONS_REQUEST_TIMEOUT_SECONDS",
  "TINKER_REVIEW_QUEUE_PATH",
  "TINKER_REVIEW_QUEUE_READ_LIMIT_WINDOW_SECONDS",
  "TINKER_REVIEW_QUEUE_READ_MAX_PEERS",
  "TINKER_REVIEW_QUEUE_READ_PEER_LIMIT",
  "TINKER_REVIEW_QUEUE_STORE_INTEGRITY_KEY_PATH",
  "TINKER_REVIEW_TICKET_TTL_SECONDS",
  "TINKER_RUN_METADATA_KEY_PATH",
  "TINKER_WALLET_AUTH_CHALLENGE_ADDRESS_LIMIT",
  "TINKER_WALLET_AUTH_CHALLENGE_CLIENT_IP_HEADER",
  "TINKER_WALLET_AUTH_CHALLENGE_GLOBAL_LIMIT",
  "TINKER_WALLET_AUTH_CHALLENGE_LIMIT_WINDOW_SECONDS",
  "TINKER_WALLET_AUTH_CHALLENGE_PEER_LIMIT",
  "TINKER_WALLET_AUTH_CHALLENGE_TRUSTED_PROXY_CIDRS",
  "TINKER_WALLET_AUTH_KEY_PATH",
  "TINKER_WALLET_AUTH_MAX_SIGNATURE_BYTES",
  "TINKER_WALLET_AUTH_RPC_MAX_RESPONSE_BYTES",
  "TINKER_WALLET_AUTH_RPC_TIMEOUT_SECONDS",
]);

// These values are product runtime policy encoded directly into the signed
// main descriptor. They are deliberately absent from Phala's mutable
// allowed-environment surface: empty explicit secret overrides force dstack
// key derivation, purpose-separated key paths prevent cross-feature key reuse,
// and durable paths bind state to the main CVM's encrypted /data volume.
export const CVM_MAIN_PRODUCT_EMBEDDED_ENVIRONMENT_KEYS = Object.freeze([
  "DSTACK_ENABLED",
  "DSTACK_SIMULATOR_ENDPOINT",
  "ORACLE_REVIEW_NOTIFICATION_CALLER_IDENTITY",
  "ORACLE_REVIEW_NOTIFICATION_RECEIPT_KEY_PATH",
  "ORACLE_REVIEW_NOTIFICATION_RECEIPT_STORE_KEY",
  "ORACLE_REVIEW_NOTIFICATION_RECEIPT_STORE_PATH",
  "ORACLE_REVIEW_NOTIFICATION_SMTP_PORT",
  "ORACLE_REVIEW_NOTIFICATION_SMTP_TIMEOUT_SECONDS",
  "TINKER_ARENA_LEGACY_INTERNAL_API_ENABLED",
  "TINKER_ARENA_STORE_INTEGRITY_KEY",
  "TINKER_ARENA_STORE_INTEGRITY_KEY_PATH",
  "TINKER_COLLABORATION_CONSENT_CHALLENGE_TTL_SECONDS",
  "TINKER_COLLABORATION_EXECUTION_GRANT_TTL_SECONDS",
  "TINKER_COLLABORATION_EXECUTION_JOURNAL_INTEGRITY_KEY",
  "TINKER_COLLABORATION_EXECUTION_JOURNAL_INTEGRITY_KEY_PATH",
  "TINKER_COLLABORATION_EXECUTION_JOURNAL_PATH",
  "TINKER_COLLABORATION_EXECUTION_POLL_INTERVAL_SECONDS",
  "TINKER_COLLABORATION_EXECUTION_WORKER_HEARTBEAT_INTEGRITY_KEY",
  "TINKER_COLLABORATION_EXECUTION_WORKER_HEARTBEAT_KEY_PATH",
  "TINKER_COLLABORATION_EXECUTION_WORKER_HEARTBEAT_PATH",
  "TINKER_COLLABORATION_EXECUTION_WORKER_HEARTBEAT_TTL_SECONDS",
  "TINKER_COLLABORATION_ROYALTY_SETTLEMENT_STORE_INTEGRITY_KEY",
  "TINKER_COLLABORATION_ROYALTY_SETTLEMENT_STORE_INTEGRITY_KEY_PATH",
  "TINKER_COLLABORATION_ROYALTY_SETTLEMENT_STORE_PATH",
  "TINKER_COLLABORATION_STORE_INTEGRITY_KEY",
  "TINKER_COLLABORATION_STORE_INTEGRITY_KEY_PATH",
  "TINKER_COLLABORATION_STORE_PATH",
  "TINKER_COLLABORATION_WALLET_AUTH_AUDIENCE",
  "TINKER_COLLABORATION_WALLET_AUTH_CHALLENGE_TTL_SECONDS",
  "TINKER_COLLABORATION_WALLET_AUTH_ISSUER",
  "TINKER_COLLABORATION_WALLET_AUTH_KEY_PATH",
  "TINKER_COLLABORATION_WALLET_AUTH_MAX_PENDING_CHALLENGES",
  "TINKER_COLLABORATION_WALLET_AUTH_SIGNING_KEY",
  "TINKER_COLLABORATION_WALLET_AUTH_TOKEN_TTL_SECONDS",
  "TINKER_CUSTOMER_AUTHORITY_PATH",
  "TINKER_CUSTOMER_CREDENTIAL_KEY_PATH",
  "TINKER_CUSTOMER_CREDENTIAL_SIGNING_KEY",
  "TINKER_CUSTOMER_SETTLEMENT_KEY_PATH",
  "TINKER_CUSTOMER_SETTLEMENT_SIGNING_KEY",
  "TINKER_CUSTOMER_STORE_INTEGRITY_KEY",
  "TINKER_CUSTOMER_STORE_INTEGRITY_KEY_PATH",
  "TINKER_CUSTOMER_STORE_PATH",
  "TINKER_EXECUTION_POLICY_STORE_INTEGRITY_KEY",
  "TINKER_REVIEW_OPERATIONS_DELEGATE_URL",
  "TINKER_REVIEW_OPERATIONS_ENABLED",
  "TINKER_REVIEW_OPERATIONS_ORACLE_AUTH_KEY_PATH",
  "TINKER_REVIEW_OPERATIONS_ORACLE_AUTH_TOKEN",
  "TINKER_REVIEW_OPERATIONS_ORACLE_URL",
  "TINKER_REVIEW_OPERATIONS_PRODUCTION_RELEASE",
  "TINKER_REVIEW_OPERATIONS_RUNTIME_AUTH_KEY_PATH",
  "TINKER_REVIEW_OPERATIONS_RUNTIME_AUTH_TOKEN",
]);

// These late values are intentionally consumed by the already-active delegate
// after the reviewed post-measurement environment update. They remain empty at
// bootstrap and every corresponding request path fails closed until the exact
// authority projector and encrypted runtime input install them. The two Arena
// release pins grant no execution authority: they only let the delegate compare
// an authenticated worker heartbeat with the reviewed release. The Tinker
// Collaboration and the Tinker customer adapter additionally require signed
// enable markers. Collaboration's marker is projected only from the current
// final-release authority; the customer runtime independently verifies its exact
// pinned authority file. All other late values are restricted to one
// initially-disabled profile.
export const CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS = Object.freeze([
  "ORACLE_REVIEW_NOTIFICATIONS_ENABLED",
  "ORACLE_REVIEW_NOTIFICATION_RECIPIENTS_JSON",
  "ORACLE_REVIEW_NOTIFICATION_RECIPIENTS_SHA256",
  "ORACLE_REVIEW_NOTIFICATION_SMTP_HOST",
  "TINKER_ARENA_REGISTRY_ADDRESS",
  "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON",
  "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
  "TINKER_ARENA_REGISTRY_RPC_URL",
  "TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH",
  "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
  "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
  "TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
  "TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN",
  "TINKER_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH",
  "TINKER_COMPUTE_WORKLOAD_QVL_URL",
  "TINKER_COMPUTE_WORKLOAD_QVL_VERIFIER_ADDRESS",
  "TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
  "TINKER_COLLABORATION_ENABLED",
  "TINKER_COLLABORATION_EXECUTION_ENABLED",
  "TINKER_COLLABORATION_EXECUTION_RELEASE_GIT_SHA",
  "TINKER_COLLABORATION_EXECUTION_RELEASE_VERIFICATION_SHA256",
  "TINKER_COLLABORATION_EXECUTION_ROYALTY_RESERVATION_SAFETY_SECONDS",
  "TINKER_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED",
  "TINKER_CUSTOMER_AUTHORITY_B64",
  "TINKER_CUSTOMER_AUTHORITY_SHA256",
  "TINKER_CUSTOMER_ENABLED",
  "TINKER_ROYALTY_ANCHOR_WRITER_RELEASE_COMMITMENT",
  "TINKER_ROYALTY_AUTHORITY_NONCE",
  "TINKER_ROYALTY_DISTRIBUTOR_ADDRESS",
  "TINKER_ROYALTY_DISTRIBUTOR_RUNTIME_CODE_HASH",
  "TINKER_ROYALTY_EXECUTION_POLICY_ANCHOR",
  "TINKER_ROYALTY_MEASUREMENT_POLICY_SHA256",
  "TINKER_ROYALTY_OWNER_ADDRESS",
  "TINKER_ROYALTY_QVL_POLICY_COMMITMENT",
  "TINKER_ROYALTY_QVL_RELEASE_POLICY_HASH",
  "TINKER_ROYALTY_QVL_SIGNER_KEY_ID",
  "TINKER_ROYALTY_QVL_VERIFIER",
  "TINKER_ROYALTY_RELEASE_POLICY_COMMITMENT",
  "TINKER_ROYALTY_SETTLEMENT_VERIFIER",
]);

// Collaboration and the customer lifecycle are late, signed-authority features,
// but the delegate itself is part of the bootstrap service set. Their booleans
// therefore need one parseable fail-closed descriptor default until their
// reviewed authority projectors install the exact live value.
export const CVM_MAIN_LATE_INPUT_FAIL_CLOSED_DEFAULTS = Object.freeze({
  ORACLE_REVIEW_NOTIFICATIONS_ENABLED: "false",
  TINKER_COLLABORATION_ENABLED: "false",
  TINKER_COLLABORATION_EXECUTION_ENABLED: "false",
  TINKER_COLLABORATION_EXECUTION_ROYALTY_RESERVATION_SAFETY_SECONDS: "900",
  TINKER_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED: "false",
  TINKER_CUSTOMER_ENABLED: "false",
});

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function environmentClassification({
  descriptorStaticKeys = [],
  provisioningResultKeys = [],
  postMeasurementDeferredKeys = [],
  postMeasurementPhaseControlKeys = [],
  descriptorDefaultedKeys = [],
  encryptedSecretKeysByPhase = {},
  embeddedOnlyKeys = [],
}) {
  const descriptor_static_keys = sortedUnique(descriptorStaticKeys);
  const provisioning_result_keys = sortedUnique(provisioningResultKeys);
  const post_measurement_deferred_keys = sortedUnique(postMeasurementDeferredKeys);
  const post_measurement_phase_control_keys = sortedUnique(
    postMeasurementPhaseControlKeys,
  );
  const descriptor_defaulted_keys = sortedUnique(descriptorDefaultedKeys);
  const encrypted_secret_environment_keys_by_phase = Object.fromEntries(
    CVM_LAUNCH_SECRET_PHASES.map((phase) => [
      phase,
      sortedUnique(encryptedSecretKeysByPhase[phase] || []),
    ]),
  );
  if (Object.keys(encryptedSecretKeysByPhase).sort().join("\n")
    !== [...CVM_LAUNCH_SECRET_PHASES].sort().join("\n")) {
    throw new Error("encrypted secret phase classification must contain the four exact phases");
  }
  const encryptedSecretEnvironmentKeys = sortedUnique(
    CVM_LAUNCH_SECRET_PHASES.flatMap(
      (phase) => encrypted_secret_environment_keys_by_phase[phase],
    ),
  );
  const classifiedSecretCount = CVM_LAUNCH_SECRET_PHASES.reduce(
    (count, phase) => count + encrypted_secret_environment_keys_by_phase[phase].length,
    0,
  );
  if (encryptedSecretEnvironmentKeys.length !== classifiedSecretCount) {
    throw new Error("encrypted secret environment phases must be pairwise disjoint");
  }
  const embedded = new Set(embeddedOnlyKeys);
  const exact_allowed_environment_keys = sortedUnique([
    ...descriptor_static_keys.filter((key) => !embedded.has(key)),
    ...provisioning_result_keys,
    ...post_measurement_deferred_keys,
    ...post_measurement_phase_control_keys,
    ...encryptedSecretEnvironmentKeys,
  ]);
  return {
    public_environment_key_classification: {
      descriptor_defaulted_keys,
      descriptor_static_keys,
      provisioning_result_keys,
      post_measurement_deferred_keys,
      post_measurement_phase_control_keys,
    },
    encrypted_secret_environment_keys_by_phase,
    exact_allowed_environment_keys,
    exact_allowed_environment_keys_sha256:
      cvmLaunchEnvironmentKeysDigest(exact_allowed_environment_keys),
  };
}

function publicEnvironmentValueAuthority(environment) {
  const classification = environment.public_environment_key_classification;
  const allowed = new Set(environment.exact_allowed_environment_keys);
  const bootstrapStaticKeys = classification.descriptor_static_keys
    .filter((key) => allowed.has(key));
  const embeddedStaticKeys = sortedUnique([
    ...classification.descriptor_static_keys.filter((key) => !allowed.has(key)),
    ...classification.descriptor_defaulted_keys,
  ]);
  const provisioningResultKeys = classification.provisioning_result_keys;
  const deferredKeys = classification.post_measurement_deferred_keys;
  const phaseControlKeys = classification.post_measurement_phase_control_keys;
  const keyClass = ({
    keys,
    keysSource,
    authorityStatus,
    sourceAuthorityRefs,
    requiredCheckpoint,
    requiredBefore,
  }) => ({
    keys_source: keysSource,
    key_count: keys.length,
    key_names_sha256: cvmLaunchEnvironmentKeysDigest(keys),
    authority_status: keys.length ? authorityStatus : "not_required_no_keys",
    source_authority_refs: keys.length ? [...sourceAuthorityRefs] : [],
    required_checkpoint: keys.length ? requiredCheckpoint : "not_required",
    required_before: keys.length ? [...requiredBefore] : [],
  });
  return {
    truth_status: CVM_PUBLIC_ENVIRONMENT_VALUE_AUTHORITY_TRUTH_STATUS,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    values_present: false,
    values_validated: false,
    bootstrap_static: keyClass({
      keys: bootstrapStaticKeys,
      keysSource:
        "classification.descriptor_static_keys_intersect_exact_allowed_environment_keys",
      authorityStatus: "required_not_implemented",
      sourceAuthorityRefs: [
        "contract_deployment_receipt_sha256",
        "deployment_intent_sha256",
        "image_release_manifest_sha256",
        "release_sha",
        "topology_sha256",
      ],
      requiredCheckpoint: "before_any_phala_sdk_call",
      requiredBefore: ["any_phala_sdk_call", "bootstrap_service_start"],
    }),
    descriptor_embedded_static: keyClass({
      keys: embeddedStaticKeys,
      keysSource:
        "classification.descriptor_static_keys_minus_allowed_plus_descriptor_defaulted_keys",
      authorityStatus: "descriptor_bytes_bound_not_injectable",
      sourceAuthorityRefs: ["deployment_intent_sha256", "topology_sha256"],
      requiredCheckpoint: "descriptor_hash_validation_before_any_phala_sdk_call",
      requiredBefore: ["any_phala_sdk_call"],
    }),
    provisioning_results: keyClass({
      keys: provisioningResultKeys,
      keysSource: "classification.provisioning_result_keys",
      authorityStatus: "required_derive_and_exactly_validate_from_prepare_not_operator_input",
      sourceAuthorityRefs: ["pinned_sdk.nextAppIds", "pinned_sdk.provisionCvm"],
      requiredCheckpoint: "after_all_seven_prepare_before_first_commit",
      requiredBefore: ["first_phala_cvm_commit"],
    }),
    post_measurement_deferred: keyClass({
      keys: deferredKeys,
      keysSource: "classification.post_measurement_deferred_keys",
      authorityStatus: "required_not_implemented",
      sourceAuthorityRefs: [
        "stage_specific_measured_cvm_authority_artifact",
        "stage_2_live_activation_authority_when_required_by_phase",
      ],
      requiredCheckpoint:
        "stage_specific_after_measurement_before_environment_update_or_service_start",
      requiredBefore: [
        "encrypted_environment_update",
        "profile_activation",
        "service_start",
      ],
    }),
    phase_control: keyClass({
      keys: phaseControlKeys,
      keysSource: "classification.post_measurement_phase_control_keys",
      authorityStatus: "policy_derived_exact_value_not_operator_free_form",
      sourceAuthorityRefs: [
        "launch_settings.initially_disabled_profiles",
        "public_environment_key_classification.post_measurement_phase_control_keys",
      ],
      requiredCheckpoint: "same_stage_as_target_profile_value_projection",
      requiredBefore: [
        "encrypted_environment_update",
        "profile_activation",
        "service_start",
      ],
    }),
  };
}

function appComposeCandidateAuthority(domain, environment) {
  return {
    authority_status:
      "reviewed_candidate_pending_pinned_adapter_and_authenticated_staging_semantics_non_executable",
    name: PHALA_CVM_APP_COMPOSE_NAMES[domain],
    manifest_version: 2,
    runner: "docker-compose",
    kms_enabled: true,
    gateway_enabled: true,
    secure_time: true,
    storage_fs: "ext4",
    tproxy_enabled: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
    allowed_envs_source: "descriptor.exact_allowed_environment_keys",
    provision_wire_transform_source:
      "PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY",
    allowed_envs_sha256: environment.exact_allowed_environment_keys_sha256,
    allowed_envs_count: environment.exact_allowed_environment_keys.length,
    docker_compose_file_sha256: null,
    docker_compose_file_byte_length: null,
    expected_compose_hash: null,
  };
}

const MAIN_ENVIRONMENT = environmentClassification({
  descriptorStaticKeys: [
    ...MAIN_STATIC_KEYS,
    ...CVM_MAIN_PRODUCT_EMBEDDED_ENVIRONMENT_KEYS,
  ],
  provisioningResultKeys: MAIN_PROVISIONING_KEYS,
  postMeasurementDeferredKeys: MAIN_DEFERRED_KEYS,
  postMeasurementPhaseControlKeys: ["COMPOSE_PROFILES"],
  descriptorDefaultedKeys: MAIN_DESCRIPTOR_DEFAULTED_KEYS,
  encryptedSecretKeysByPhase: MAIN_SECRET_KEYS_BY_PHASE,
  embeddedOnlyKeys: [
    ...CVM_MAIN_PRODUCT_EMBEDDED_ENVIRONMENT_KEYS,
    "TINKER_COMPUTE_WORKLOAD_CHAIN_ID",
    "TINKER_WALLET_AUTH_CHAIN_ID",
    "TINKER_WALLET_AUTH_DOMAIN",
    "TINKER_WALLET_AUTH_URI",
  ],
});

const QVL_ENVIRONMENT = environmentClassification({
  descriptorStaticKeys: QVL_NUMERIC_KEYS,
  postMeasurementPhaseControlKeys: ["COMPOSE_PROFILES"],
  encryptedSecretKeysByPhase: {
    bootstrap_provision: [],
    post_measurement_policy_bootstrap: ["QVL_AUTH_TOKEN", "QVL_RELEASE_POLICY_B64"],
    final_authority_runtime: [],
    anchor_writer_ceremony: [],
  },
  embeddedOnlyKeys: QVL_NUMERIC_KEYS,
});

const METERING_ENVIRONMENT = environmentClassification({
  descriptorStaticKeys: [
    "METERING_CEREMONY_NONCE",
    "METERING_DEPLOYMENT_INTENT_SHA256",
    "METERING_QVL_MEASUREMENT_POLICY_SHA256",
  ],
  provisioningResultKeys: ["METERING_CVM_ID"],
  postMeasurementDeferredKeys: [
    "METERING_QVL_RELEASE_POLICY_HASH",
    "METERING_QVL_URL",
    "METERING_QVL_VERIFIER_ADDRESS",
    "METERING_RELEASE_AUTHORITY_SHA256",
  ],
  postMeasurementPhaseControlKeys: ["COMPOSE_PROFILES"],
  encryptedSecretKeysByPhase: {
    bootstrap_provision: [],
    post_measurement_policy_bootstrap: [
      "METERING_AUTH_TOKEN",
      "METERING_POLICY_SET_B64",
      "METERING_QVL_AUTH_TOKEN",
      "METERING_RPC_URL",
    ],
    final_authority_runtime: [],
    anchor_writer_ceremony: [],
  },
});

function launchSettings(domain) {
  const main = domain === "main_runtime_cvm";
  const qvl = domain.endsWith("_qvl_cvm");
  return {
    platform: "phala_cloud",
    phala_cli_version: "v1.1.19+d2300dd",
    phala_cloud_sdk_version: "0.2.10",
    phala_os_image: PHALA_OS_IMAGE_CATALOG_ENTRY.name,
    phala_os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
    phala_os_image_catalog_entry: { ...PHALA_OS_IMAGE_CATALOG_ENTRY },
    phala_os_image_catalog_entry_sha256:
      phalaOsImageCatalogEntryDigest(PHALA_OS_IMAGE_CATALOG_ENTRY),
    cvm_resource_target: structuredClone(PHALA_CVM_RESOURCE_TARGETS[domain]),
    cvm_resource_profile_request_semantics:
      "send_instance_type_and_disk_size_omit_node_id_and_region_for_bound_automatic_best_match",
    cvm_resource_profile_verification:
      "exact_prepare_response_and_commit_verification_required_not_implemented",
    fresh_cvm_required: true,
    fresh_cli_deploy_forbidden: true,
    provisioning_api: "provisionCvm_validate_all_seven_then_commitCvmProvision",
    deployment_flags: {
      no_dev_os: true,
      no_listed: true,
      no_public_logs: true,
      no_public_sysinfo: true,
    },
    post_create_assertions: {
      listed: false,
      os_is_dev: false,
      public_logs: false,
      public_sysinfo: false,
      public_tcbinfo: false,
    },
    environment_update_policy: "encrypted_exact_allowed_keys_only",
    initial_phase: "bootstrap_provision",
    initial_services: main
      ? [
          "delegate",
          "diligence-policy-init",
          "neko",
          "oracle",
          "tinker-customer-authority-init",
        ]
      : [],
    initially_enabled_profiles: [],
    initially_disabled_profiles: main
      ? [
          "anchor-writer-ceremony",
          "arena-runtime",
          "collaboration-execution",
          "compute-execution",
          "deal-settlement",
          "mailbox-genesis",
          "review-operations",
          "tinker-account-genesis",
        ]
      : [qvl ? "qvl-runtime" : "metering-runtime"],
  };
}

export const CVM_LAUNCH_DESCRIPTOR_POLICY = Object.freeze(Object.fromEntries(
  CVM_LAUNCH_DOMAINS.map((domain) => {
    const environment = domain === "main_runtime_cvm"
      ? MAIN_ENVIRONMENT
      : (domain.endsWith("_qvl_cvm") ? QVL_ENVIRONMENT : METERING_ENVIRONMENT);
    return [domain, Object.freeze({
      trust_domain: domain,
      descriptor_file: CVM_LAUNCH_DESCRIPTOR_FILES[domain],
      launch_settings: launchSettings(domain),
      ...environment,
      public_environment_value_authority:
        publicEnvironmentValueAuthority(environment),
      app_compose_candidate: appComposeCandidateAuthority(domain, environment),
    })];
  }),
));

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;

export const CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS = Object.freeze([
  Object.freeze({ ledger_key: "challengeRegistry", name: "ChallengeRegistry" }),
  Object.freeze({ ledger_key: "computeCreditVault", name: "ComputeCreditVault" }),
  Object.freeze({ ledger_key: "diligenceRoom", name: "DiligenceRoom" }),
  Object.freeze({ ledger_key: "emailOracleAuth", name: "EmailOracleAuth" }),
  Object.freeze({ ledger_key: "executionPolicyAnchor", name: "ExecutionPolicyAnchor" }),
  Object.freeze({ ledger_key: "royaltyDistributor", name: "RoyaltyDistributor" }),
  Object.freeze({ ledger_key: "tinkerAccountEncumbrance", name: "TinkerAccountEncumbrance" }),
]);

export const FRESH_DEPLOYMENT_TRANSACTION_SPEC = Object.freeze([
  Object.freeze({
    contract_key: "diligenceRoom",
    name: "DiligenceRoom",
    transaction_type: "CREATE",
    function_signature: "constructor(bool,address)",
  }),
  Object.freeze({
    contract_key: "diligenceRoom",
    name: "DiligenceRoom",
    transaction_type: "CALL",
    function_signature: "freezeFeeBps()",
  }),
  Object.freeze({
    contract_key: "diligenceRoom",
    name: "DiligenceRoom",
    transaction_type: "CALL",
    function_signature: "enableComputeSettlementPolicy()",
  }),
  Object.freeze({
    contract_key: "diligenceRoom",
    name: "DiligenceRoom",
    transaction_type: "CALL",
    function_signature: "setComposeApprovalRequired(bool)",
  }),
  Object.freeze({
    contract_key: "diligenceRoom",
    name: "DiligenceRoom",
    transaction_type: "CALL",
    function_signature: "setTeeIdentityApprovalRequired(bool)",
  }),
  Object.freeze({
    contract_key: "diligenceRoom",
    name: "DiligenceRoom",
    transaction_type: "CALL",
    function_signature: "freezeApprovalRequirements()",
  }),
  Object.freeze({
    contract_key: "tinkerAccountEncumbrance",
    name: "TinkerAccountEncumbrance",
    transaction_type: "CREATE",
    function_signature: "constructor(address,bytes32,bytes32,uint256,uint256)",
  }),
  Object.freeze({
    contract_key: "royaltyDistributor",
    name: "RoyaltyDistributor",
    transaction_type: "CREATE",
    function_signature: "constructor(address)",
  }),
  Object.freeze({
    contract_key: "challengeRegistry",
    name: "ChallengeRegistry",
    transaction_type: "CREATE",
    function_signature: "constructor(address)",
  }),
  Object.freeze({
    contract_key: "computeCreditVault",
    name: "ComputeCreditVault",
    transaction_type: "CREATE",
    function_signature: "constructor(address,address,uint16)",
  }),
  Object.freeze({
    contract_key: "computeCreditVault",
    name: "ComputeCreditVault",
    transaction_type: "CALL",
    function_signature: "freezeDeveloperFee()",
  }),
  Object.freeze({
    contract_key: "emailOracleAuth",
    name: "EmailOracleAuth",
    transaction_type: "CREATE",
    function_signature: "constructor(address,uint256,bool,bytes32,bytes32,bool)",
  }),
  Object.freeze({
    contract_key: "executionPolicyAnchor",
    name: "ExecutionPolicyAnchor",
    transaction_type: "CREATE",
    function_signature: "constructor(address,bytes32,bytes32)",
  }),
]);

// Historical v3 receipts predate the operator-owned RoyaltyDistributor v2
// constructor. Keep their exact transaction vocabulary independently frozen so
// a current release evolution cannot silently reinterpret historical evidence.
const FRESH_DEPLOYMENT_TRANSACTION_SPEC_V3 = Object.freeze(
  FRESH_DEPLOYMENT_TRANSACTION_SPEC.map((entry) => Object.freeze(
    entry.contract_key === "royaltyDistributor"
      ? { ...entry, function_signature: "constructor()" }
      : { ...entry },
  )),
);

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} fields are not exact`);
  }
  return value;
}

function exactString(value, expected, label) {
  if (value !== expected) throw new Error(`${label} must equal ${expected}`);
  return expected;
}

function normalizedSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value) || value === ZERO_SHA256) {
    throw new Error(`${label} must be a nonzero sha256:<64 lowercase hex> digest`);
  }
  return value;
}

function normalizedReleaseSha(value, label = "release_sha") {
  if (typeof value !== "string" || !SHA40.test(value) || value === "0".repeat(40)) {
    throw new Error(`${label} must be a nonzero 40-character lowercase release SHA`);
  }
  return value;
}

function normalizedEnvironmentKeys(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  const normalized = value.map((key, index) => {
    if (typeof key !== "string" || !ENVIRONMENT_KEY.test(key)) {
      throw new Error(`${label}[${index}] must be a canonical public environment key name`);
    }
    return key;
  });
  if (JSON.stringify(normalized) !== JSON.stringify(sortedUnique(normalized))) {
    throw new Error(`${label} must be sorted and duplicate-free`);
  }
  return normalized;
}

function normalizedStringArray(value, expected, label) {
  if (!Array.isArray(value)
    || value.some((item) => typeof item !== "string")
    || JSON.stringify(value) !== JSON.stringify(expected)) {
    throw new Error(`${label} must equal the canonical ordered list`);
  }
  return [...expected];
}

function normalizedPhalaOsImageCatalogEntry(value, label) {
  const parsed = exactRecord(value, [
    "name",
    "slug",
    "version",
    "os_image_hash",
    "is_dev",
    "requires_gpu",
  ], label);
  for (const [key, expected] of Object.entries(PHALA_OS_IMAGE_CATALOG_ENTRY)) {
    if (parsed[key] !== expected) {
      throw new Error(`${label}.${key} is not the exact reviewed production catalog value`);
    }
  }
  return { ...PHALA_OS_IMAGE_CATALOG_ENTRY };
}

function normalizedLaunchSettings(value, expected, label) {
  const parsed = exactRecord(value, [
    "platform",
    "phala_cli_version",
    "phala_cloud_sdk_version",
    "phala_os_image",
    "phala_os_image_hash",
    "phala_os_image_catalog_entry",
    "phala_os_image_catalog_entry_sha256",
    "cvm_resource_target",
    "cvm_resource_profile_request_semantics",
    "cvm_resource_profile_verification",
    "fresh_cvm_required",
    "fresh_cli_deploy_forbidden",
    "provisioning_api",
    "deployment_flags",
    "post_create_assertions",
    "environment_update_policy",
    "initial_phase",
    "initial_services",
    "initially_enabled_profiles",
    "initially_disabled_profiles",
  ], label);
  const flags = exactRecord(parsed.deployment_flags, [
    "no_dev_os",
    "no_listed",
    "no_public_logs",
    "no_public_sysinfo",
  ], `${label}.deployment_flags`);
  const assertions = exactRecord(parsed.post_create_assertions, [
    "listed",
    "os_is_dev",
    "public_logs",
    "public_sysinfo",
    "public_tcbinfo",
  ], `${label}.post_create_assertions`);
  const catalogEntry = normalizedPhalaOsImageCatalogEntry(
    parsed.phala_os_image_catalog_entry,
    `${label}.phala_os_image_catalog_entry`,
  );
  const resourceTarget = exactRecord(parsed.cvm_resource_target, [
    "authority_status",
    "instance_type",
    "disk_size",
    "placement",
  ], `${label}.cvm_resource_target`);
  exactRecord(resourceTarget.placement, [
    "selection_mode",
    "node_id",
    "region",
  ], `${label}.cvm_resource_target.placement`);
  if (JSON.stringify(sortedObject(resourceTarget))
      !== JSON.stringify(sortedObject(expected.cvm_resource_target))) {
    throw new Error(`${label}.cvm_resource_target is not the exact pending reviewed resource target`);
  }
  if (parsed.phala_os_image !== catalogEntry.name
    || parsed.phala_os_image_hash !== catalogEntry.os_image_hash
    || catalogEntry.is_dev !== false
    || catalogEntry.requires_gpu !== false) {
    throw new Error(`${label} OS selector/hash must bind the reviewed non-dev non-GPU catalog entry`);
  }
  if (parsed.phala_os_image_catalog_entry_sha256
    !== phalaOsImageCatalogEntryDigest(catalogEntry)) {
    throw new Error(`${label}.phala_os_image_catalog_entry_sha256 does not commit the reviewed catalog entry`);
  }
  const scalarKeys = [
    "platform",
    "phala_cli_version",
    "phala_cloud_sdk_version",
    "phala_os_image",
    "phala_os_image_hash",
    "phala_os_image_catalog_entry_sha256",
    "cvm_resource_profile_request_semantics",
    "cvm_resource_profile_verification",
    "fresh_cvm_required",
    "fresh_cli_deploy_forbidden",
    "provisioning_api",
    "environment_update_policy",
    "initial_phase",
  ];
  for (const key of scalarKeys) {
    if (parsed[key] !== expected[key]) throw new Error(`${label}.${key} is not the reviewed launch setting`);
  }
  for (const key of Object.keys(expected.deployment_flags)) {
    if (flags[key] !== expected.deployment_flags[key]) throw new Error(`${label}.deployment_flags.${key} is not hardened`);
  }
  for (const key of Object.keys(expected.post_create_assertions)) {
    if (assertions[key] !== expected.post_create_assertions[key]) throw new Error(`${label}.post_create_assertions.${key} is not fail-closed`);
  }
  return {
    platform: expected.platform,
    phala_cli_version: expected.phala_cli_version,
    phala_cloud_sdk_version: expected.phala_cloud_sdk_version,
    phala_os_image: expected.phala_os_image,
    phala_os_image_hash: expected.phala_os_image_hash,
    phala_os_image_catalog_entry: { ...expected.phala_os_image_catalog_entry },
    phala_os_image_catalog_entry_sha256:
      expected.phala_os_image_catalog_entry_sha256,
    cvm_resource_target: structuredClone(expected.cvm_resource_target),
    cvm_resource_profile_request_semantics:
      expected.cvm_resource_profile_request_semantics,
    cvm_resource_profile_verification:
      expected.cvm_resource_profile_verification,
    fresh_cvm_required: expected.fresh_cvm_required,
    fresh_cli_deploy_forbidden: expected.fresh_cli_deploy_forbidden,
    provisioning_api: expected.provisioning_api,
    deployment_flags: { ...expected.deployment_flags },
    post_create_assertions: { ...expected.post_create_assertions },
    environment_update_policy: expected.environment_update_policy,
    initial_phase: expected.initial_phase,
    initial_services: normalizedStringArray(
      parsed.initial_services,
      expected.initial_services,
      `${label}.initial_services`,
    ),
    initially_enabled_profiles: normalizedStringArray(
      parsed.initially_enabled_profiles,
      expected.initially_enabled_profiles,
      `${label}.initially_enabled_profiles`,
    ),
    initially_disabled_profiles: normalizedStringArray(
      parsed.initially_disabled_profiles,
      expected.initially_disabled_profiles,
      `${label}.initially_disabled_profiles`,
    ),
  };
}

function normalizedClassification(value, expected, label) {
  const parsed = exactRecord(value, [
    "descriptor_defaulted_keys",
    "descriptor_static_keys",
    "provisioning_result_keys",
    "post_measurement_deferred_keys",
    "post_measurement_phase_control_keys",
  ], label);
  const output = {};
  for (const key of [
    "descriptor_defaulted_keys",
    "descriptor_static_keys",
    "provisioning_result_keys",
    "post_measurement_deferred_keys",
    "post_measurement_phase_control_keys",
  ]) {
    output[key] = normalizedEnvironmentKeys(parsed[key], `${label}.${key}`);
    if (JSON.stringify(output[key]) !== JSON.stringify(expected[key])) {
      throw new Error(`${label}.${key} does not equal the canonical descriptor policy`);
    }
  }
  return output;
}

function normalizedSecretPhases(value, expected, label) {
  const parsed = exactRecord(value, CVM_LAUNCH_SECRET_PHASES, label);
  const output = {};
  const all = [];
  for (const phase of CVM_LAUNCH_SECRET_PHASES) {
    output[phase] = normalizedEnvironmentKeys(parsed[phase], `${label}.${phase}`);
    if (JSON.stringify(output[phase]) !== JSON.stringify(expected[phase])) {
      throw new Error(`${label}.${phase} does not equal the canonical secret phase policy`);
    }
    all.push(...output[phase]);
  }
  if (new Set(all).size !== all.length) {
    throw new Error(`${label} phase sets must be pairwise disjoint`);
  }
  return output;
}

function normalizedPublicEnvironmentValueAuthority(value, expected, label) {
  const parsed = exactRecord(value, [
    "truth_status",
    "projector_schema",
    "values_present",
    "values_validated",
    "bootstrap_static",
    "descriptor_embedded_static",
    "provisioning_results",
    "post_measurement_deferred",
    "phase_control",
  ], label);
  for (const key of [
    "bootstrap_static",
    "descriptor_embedded_static",
    "provisioning_results",
    "post_measurement_deferred",
    "phase_control",
  ]) {
    exactRecord(parsed[key], [
      "keys_source",
      "key_count",
      "key_names_sha256",
      "authority_status",
      "source_authority_refs",
      "required_checkpoint",
      "required_before",
    ], `${label}.${key}`);
  }
  if (JSON.stringify(sortedObject(parsed)) !== JSON.stringify(sortedObject(expected))) {
    throw new Error(`${label} does not equal the exact value-free public-value gate contract`);
  }
  return structuredClone(expected);
}

function normalizedSealedProductionExecutionPolicy(value) {
  const parsed = exactRecord(value, [
    "schema",
    "availability",
    "reason_code",
    "blocker_codes",
    "caller_supplied_callbacks_accepted",
    "caller_supplied_clients_accepted",
    "manual_cli_or_sdk_bypass_authorized",
  ], "sealed_production_execution_policy");
  if (JSON.stringify(sortedObject(parsed))
      !== JSON.stringify(sortedObject(PHALA_PRODUCTION_EXECUTION_POLICY))) {
    throw new Error(
      "sealed_production_execution_policy must equal the exact canonical production policy",
    );
  }
  return structuredClone(PHALA_PRODUCTION_EXECUTION_POLICY);
}

function normalizedPhalaControlPlaneAuthority(value) {
  const parsed = exactRecord(value, [
    "api_origin",
    "api_version",
    "redirects_allowed",
    "origin_drift_allowed",
    "phala_cloud_api_prefix_environment_override_allowed",
    "default_discovery_allowed",
    "adapter_status",
  ], "phala_control_plane_authority");
  if (JSON.stringify(sortedObject(parsed))
      !== JSON.stringify(sortedObject(PHALA_CONTROL_PLANE_AUTHORITY))) {
    throw new Error(
      "phala_control_plane_authority must equal the exact pinned origin and API version policy",
    );
  }
  return structuredClone(PHALA_CONTROL_PLANE_AUTHORITY);
}

function normalizedExactTopLevelPolicy(value, expected, label) {
  const parsed = exactRecord(value, Object.keys(expected), label);
  if (JSON.stringify(sortedObject(parsed)) !== JSON.stringify(sortedObject(expected))) {
    throw new Error(`${label} must equal the exact fail-closed launch policy`);
  }
  return structuredClone(expected);
}

function normalizedAppComposeCandidate(value, expected, descriptorSha256, label) {
  const parsed = exactRecord(value, [
    "authority_status",
    "name",
    "manifest_version",
    "runner",
    "kms_enabled",
    "gateway_enabled",
    "secure_time",
    "storage_fs",
    "tproxy_enabled",
    "public_logs",
    "public_sysinfo",
    "public_tcbinfo",
    "allowed_envs_source",
    "provision_wire_transform_source",
    "allowed_envs_sha256",
    "allowed_envs_count",
    "docker_compose_file_sha256",
    "docker_compose_file_byte_length",
    "expected_compose_hash",
  ], label);
  for (const key of [
    "authority_status",
    "name",
    "manifest_version",
    "runner",
    "kms_enabled",
    "gateway_enabled",
    "secure_time",
    "storage_fs",
    "tproxy_enabled",
    "public_logs",
    "public_sysinfo",
    "public_tcbinfo",
    "allowed_envs_source",
    "provision_wire_transform_source",
    "allowed_envs_sha256",
    "allowed_envs_count",
  ]) {
    if (parsed[key] !== expected[key]) {
      throw new Error(`${label}.${key} is not the exact reviewed AppCompose candidate policy`);
    }
  }
  const composeFileSha256 = normalizedSha256(
    parsed.docker_compose_file_sha256,
    `${label}.docker_compose_file_sha256`,
  );
  if (composeFileSha256 !== descriptorSha256) {
    throw new Error(`${label}.docker_compose_file_sha256 must equal descriptor_sha256`);
  }
  if (!Number.isSafeInteger(parsed.docker_compose_file_byte_length)
    || parsed.docker_compose_file_byte_length < 1
    || parsed.docker_compose_file_byte_length > 200 * 1024) {
    throw new Error(`${label}.docker_compose_file_byte_length is invalid`);
  }
  if (typeof parsed.expected_compose_hash !== "string"
    || !BARE_SHA256.test(parsed.expected_compose_hash)
    || parsed.expected_compose_hash === "0".repeat(64)) {
    throw new Error(`${label}.expected_compose_hash must be nonzero bare lowercase SHA-256`);
  }
  return {
    ...structuredClone(expected),
    docker_compose_file_sha256: composeFileSha256,
    docker_compose_file_byte_length: parsed.docker_compose_file_byte_length,
    expected_compose_hash: parsed.expected_compose_hash,
  };
}

function normalizedDescriptor(value, expected, index) {
  const label = `descriptors[${index}]`;
  const parsed = exactRecord(value, [
    "trust_domain",
    "descriptor_file",
    "descriptor_sha256",
    "descriptor_hash_semantics",
    "launch_settings",
    "public_environment_key_classification",
    "public_environment_value_authority",
    "app_compose_candidate",
    "encrypted_secret_environment_keys_by_phase",
    "exact_allowed_environment_keys",
    "exact_allowed_environment_keys_sha256",
  ], label);
  exactString(parsed.trust_domain, expected.trust_domain, `${label}.trust_domain`);
  exactString(parsed.descriptor_file, expected.descriptor_file, `${label}.descriptor_file`);
  exactString(
    parsed.descriptor_hash_semantics,
    "raw_descriptor_bytes_sha256_not_phala_compose_hash",
    `${label}.descriptor_hash_semantics`,
  );
  const descriptorSha256 = normalizedSha256(
    parsed.descriptor_sha256,
    `${label}.descriptor_sha256`,
  );
  const classification = normalizedClassification(
    parsed.public_environment_key_classification,
    expected.public_environment_key_classification,
    `${label}.public_environment_key_classification`,
  );
  const secretPhases = normalizedSecretPhases(
    parsed.encrypted_secret_environment_keys_by_phase,
    expected.encrypted_secret_environment_keys_by_phase,
    `${label}.encrypted_secret_environment_keys_by_phase`,
  );
  const publicValueAuthority = normalizedPublicEnvironmentValueAuthority(
    parsed.public_environment_value_authority,
    expected.public_environment_value_authority,
    `${label}.public_environment_value_authority`,
  );
  const appComposeCandidate = normalizedAppComposeCandidate(
    parsed.app_compose_candidate,
    expected.app_compose_candidate,
    descriptorSha256,
    `${label}.app_compose_candidate`,
  );
  const secrets = sortedUnique(
    CVM_LAUNCH_SECRET_PHASES.flatMap((phase) => secretPhases[phase]),
  );
  const allowed = normalizedEnvironmentKeys(
    parsed.exact_allowed_environment_keys,
    `${label}.exact_allowed_environment_keys`,
  );
  if (JSON.stringify(allowed) !== JSON.stringify(expected.exact_allowed_environment_keys)) {
    throw new Error(`${label}.exact_allowed_environment_keys does not equal the canonical descriptor policy`);
  }
  const keyHash = normalizedSha256(
    parsed.exact_allowed_environment_keys_sha256,
    `${label}.exact_allowed_environment_keys_sha256`,
  );
  if (keyHash !== cvmLaunchEnvironmentKeysDigest(allowed)) {
    throw new Error(`${label}.exact_allowed_environment_keys_sha256 does not bind the exact names`);
  }
  const publicNames = sortedUnique([
    ...classification.descriptor_defaulted_keys,
    ...classification.descriptor_static_keys,
    ...classification.provisioning_result_keys,
    ...classification.post_measurement_deferred_keys,
    ...classification.post_measurement_phase_control_keys,
  ]);
  if (publicNames.some((key) => secrets.includes(key))) {
    throw new Error(`${label} public and encrypted-secret key classifications must be disjoint`);
  }
  if (allowed.includes("PHALA_CLOUD_API_KEY") || publicNames.includes("PHALA_CLOUD_API_KEY")) {
    throw new Error(`${label} must never allow the Phala control-plane credential into a CVM`);
  }
  return {
    trust_domain: expected.trust_domain,
    descriptor_file: expected.descriptor_file,
    descriptor_sha256: descriptorSha256,
    descriptor_hash_semantics: "raw_descriptor_bytes_sha256_not_phala_compose_hash",
    launch_settings: normalizedLaunchSettings(
      parsed.launch_settings,
      expected.launch_settings,
      `${label}.launch_settings`,
    ),
    public_environment_key_classification: classification,
    public_environment_value_authority: publicValueAuthority,
    app_compose_candidate: appComposeCandidate,
    encrypted_secret_environment_keys_by_phase: secretPhases,
    exact_allowed_environment_keys: allowed,
    exact_allowed_environment_keys_sha256: keyHash,
  };
}

export function normalizeCvmLaunchIntentCore(value) {
  const parsed = exactRecord(value, [
    "schema",
    "truth_status",
    "release_sha",
    "network",
    "deployment_intent_sha256",
    "contract_deployment_receipt_sha256",
    "topology_sha256",
    "image_release_manifest_sha256",
    "image_attestation_bundle_sha256",
    "phala_control_plane_authority",
    "phala_workspace_account_target_authority",
    "phala_sdk_debug_secret_logging_policy",
    "phala_cloud_sdk_wire_transform_authority",
    "phala_provision_request_authority",
    "compose_hash_authority",
    "sealed_production_execution_policy",
    "dynamic_runtime_authorities",
    "descriptors",
  ], "cvm launch intent");
  exactString(parsed.schema, CVM_LAUNCH_INTENT_CORE_SCHEMA, "schema");
  exactString(parsed.truth_status, CVM_LAUNCH_TRUTH_STATUS, "truth_status");
  const network = exactRecord(parsed.network, ["chain_id", "name"], "network");
  if (network.chain_id !== BASE_SEPOLIA_CHAIN_ID || network.name !== BASE_SEPOLIA_NAME) {
    throw new Error("network must be Base Sepolia chain 84532");
  }
  if (!Array.isArray(parsed.descriptors)
    || parsed.descriptors.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("descriptors must contain the seven canonical trust domains");
  }
  const dynamicRuntimeAuthorities = exactRecord(parsed.dynamic_runtime_authorities, [
    "endpoint_origins",
    "os_image_hashes",
    "phala_app_ids",
    "phala_cvm_ids",
    "platform_compose_hashes",
    "qvl_release_policy_hashes",
    "tee_identities",
    "verifier_addresses",
  ], "dynamic_runtime_authorities");
  const emptyDynamicRuntimeAuthorities = {};
  for (const key of [
    "endpoint_origins",
    "os_image_hashes",
    "phala_app_ids",
    "phala_cvm_ids",
    "platform_compose_hashes",
    "qvl_release_policy_hashes",
    "tee_identities",
    "verifier_addresses",
  ]) {
    if (!Array.isArray(dynamicRuntimeAuthorities[key])
      || dynamicRuntimeAuthorities[key].length !== 0) {
      throw new Error(`dynamic_runtime_authorities.${key} must be an explicit empty array before CVM deployment`);
    }
    emptyDynamicRuntimeAuthorities[key] = [];
  }
  return {
    schema: CVM_LAUNCH_INTENT_CORE_SCHEMA,
    truth_status: CVM_LAUNCH_TRUTH_STATUS,
    release_sha: normalizedReleaseSha(parsed.release_sha),
    network: { chain_id: BASE_SEPOLIA_CHAIN_ID, name: BASE_SEPOLIA_NAME },
    deployment_intent_sha256: normalizedSha256(
      parsed.deployment_intent_sha256,
      "deployment_intent_sha256",
    ),
    contract_deployment_receipt_sha256: normalizedSha256(
      parsed.contract_deployment_receipt_sha256,
      "contract_deployment_receipt_sha256",
    ),
    topology_sha256: normalizedSha256(parsed.topology_sha256, "topology_sha256"),
    image_release_manifest_sha256: normalizedSha256(
      parsed.image_release_manifest_sha256,
      "image_release_manifest_sha256",
    ),
    image_attestation_bundle_sha256: normalizedSha256(
      parsed.image_attestation_bundle_sha256,
      "image_attestation_bundle_sha256",
    ),
    phala_control_plane_authority: normalizedPhalaControlPlaneAuthority(
      parsed.phala_control_plane_authority,
    ),
    phala_workspace_account_target_authority: normalizedExactTopLevelPolicy(
      parsed.phala_workspace_account_target_authority,
      PHALA_WORKSPACE_ACCOUNT_TARGET_AUTHORITY,
      "phala_workspace_account_target_authority",
    ),
    phala_sdk_debug_secret_logging_policy: normalizedExactTopLevelPolicy(
      parsed.phala_sdk_debug_secret_logging_policy,
      PHALA_SDK_DEBUG_SECRET_LOGGING_POLICY,
      "phala_sdk_debug_secret_logging_policy",
    ),
    phala_cloud_sdk_wire_transform_authority: normalizedExactTopLevelPolicy(
      parsed.phala_cloud_sdk_wire_transform_authority,
      PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY,
      "phala_cloud_sdk_wire_transform_authority",
    ),
    phala_provision_request_authority: normalizedExactTopLevelPolicy(
      parsed.phala_provision_request_authority,
      PHALA_PROVISION_REQUEST_AUTHORITY,
      "phala_provision_request_authority",
    ),
    compose_hash_authority: normalizedExactTopLevelPolicy(
      parsed.compose_hash_authority,
      PHALA_DSTACK_COMPOSE_HASH_AUTHORITY,
      "compose_hash_authority",
    ),
    sealed_production_execution_policy: normalizedSealedProductionExecutionPolicy(
      parsed.sealed_production_execution_policy,
    ),
    dynamic_runtime_authorities: emptyDynamicRuntimeAuthorities,
    descriptors: CVM_LAUNCH_DOMAINS.map((domain, index) => normalizedDescriptor(
      parsed.descriptors[index],
      CVM_LAUNCH_DESCRIPTOR_POLICY[domain],
      index,
    )),
  };
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((item) => sortedObject(item));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

export function phalaDstackComposeHash(appCompose) {
  const parsed = exactRecord(
    appCompose,
    PHALA_DSTACK_APP_COMPOSE_HASH_INPUT_KEYS,
    "AppCompose hash input",
  );
  if (typeof parsed.name !== "string" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(parsed.name)
    || parsed.manifest_version !== 2
    || parsed.runner !== "docker-compose"
    || typeof parsed.docker_compose_file !== "string"
    || Buffer.byteLength(parsed.docker_compose_file, "utf8") < 1
    || Buffer.byteLength(parsed.docker_compose_file, "utf8") > 200 * 1024
    || parsed.kms_enabled !== true
    || parsed.gateway_enabled !== true
    || parsed.secure_time !== true
    || parsed.storage_fs !== "ext4"
    || parsed.tproxy_enabled !== false
    || parsed.public_logs !== false
    || parsed.public_sysinfo !== false
    || parsed.public_tcbinfo !== false) {
    throw new Error("AppCompose hash input is not the exact reviewed candidate shape");
  }
  normalizedEnvironmentKeys(parsed.allowed_envs, "AppCompose hash input.allowed_envs");
  return createHash("sha256")
    .update(Buffer.from(JSON.stringify(sortedObject(parsed)), "utf8"))
    .digest("hex");
}

export function createPhalaDstackComposeHashInput(
  candidate,
  descriptorText,
  allowedEnvs,
) {
  if (!isRecord(candidate)) throw new Error("AppCompose candidate must be an object");
  const input = {
    name: candidate.name,
    manifest_version: candidate.manifest_version,
    runner: candidate.runner,
    docker_compose_file: descriptorText,
    kms_enabled: candidate.kms_enabled,
    gateway_enabled: candidate.gateway_enabled,
    secure_time: candidate.secure_time,
    storage_fs: candidate.storage_fs,
    tproxy_enabled: candidate.tproxy_enabled,
    public_logs: candidate.public_logs,
    public_sysinfo: candidate.public_sysinfo,
    public_tcbinfo: candidate.public_tcbinfo,
    allowed_envs: [...allowedEnvs],
  };
  // Reuse the exact hash-input validator here so the object inspected in review
  // is byte-for-byte the object accepted by the local compose-hash projector.
  phalaDstackComposeHash(input);
  return input;
}

export function canonicalCvmLaunchIntentCoreArtifactText(value) {
  return `${JSON.stringify(sortedObject(normalizeCvmLaunchIntentCore(value)), null, 2)}\n`;
}

export function cvmLaunchIntentCoreDigest(value) {
  const normalized = normalizeCvmLaunchIntentCore(value);
  return createHash("sha256")
    .update(Buffer.from(CVM_LAUNCH_INTENT_DOMAIN, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(normalized)), "utf8"))
    .digest("hex");
}

export function cvmLaunchEnvironmentKeysDigest(keys) {
  const normalized = normalizedEnvironmentKeys(keys, "environment keys");
  const payload = normalized.length ? `${normalized.join("\n")}\n` : "";
  return `sha256:${createHash("sha256")
    .update(Buffer.from(CVM_LAUNCH_ENVIRONMENT_KEYS_DOMAIN, "utf8"))
    .update(Buffer.from(payload, "utf8"))
    .digest("hex")}`;
}

export function phalaOsImageCatalogEntryDigest(entry) {
  const parsed = normalizedPhalaOsImageCatalogEntry(
    entry,
    "Phala OS image catalog entry",
  );
  return `sha256:${createHash("sha256")
    .update(Buffer.from(CVM_LAUNCH_OS_IMAGE_CATALOG_ENTRY_DOMAIN, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(parsed)), "utf8"))
    .digest("hex")}`;
}

export function phalaProductionExecutionPolicyDigest(
  policy = PHALA_PRODUCTION_EXECUTION_POLICY,
) {
  const normalized = normalizedSealedProductionExecutionPolicy(policy);
  return rawSha256(Buffer.from(JSON.stringify(sortedObject(normalized)), "utf8"));
}

export function parseCvmLaunchIntentCoreText(text) {
  const source = String(text);
  const bytes = Buffer.byteLength(source, "utf8");
  if (bytes < 1 || bytes > MAX_CVM_LAUNCH_INTENT_BYTES) {
    throw new Error(`CVM launch intent must be between 1 and ${MAX_CVM_LAUNCH_INTENT_BYTES} UTF-8 bytes`);
  }
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error("CVM launch intent must be valid JSON");
  }
  const normalized = normalizeCvmLaunchIntentCore(parsed);
  const canonical = canonicalCvmLaunchIntentCoreArtifactText(normalized);
  if (source !== canonical) {
    throw new Error("CVM launch intent must use normalized sorted two-space JSON with one trailing newline");
  }
  return normalized;
}

export function cvmLaunchIntentValidationReceipt(value) {
  const normalized = normalizeCvmLaunchIntentCore(value);
  const publicKeys = normalized.descriptors.reduce((count, descriptor) => (
    count
      + descriptor.public_environment_key_classification.descriptor_static_keys.length
      + descriptor.public_environment_key_classification.descriptor_defaulted_keys.length
      + descriptor.public_environment_key_classification.provisioning_result_keys.length
      + descriptor.public_environment_key_classification.post_measurement_deferred_keys.length
      + descriptor.public_environment_key_classification.post_measurement_phase_control_keys.length
  ), 0);
  const secretKeys = normalized.descriptors.reduce(
    (count, descriptor) => count + CVM_LAUNCH_SECRET_PHASES.reduce(
      (phaseCount, phase) => phaseCount
        + descriptor.encrypted_secret_environment_keys_by_phase[phase].length,
      0,
    ),
    0,
  );
  const publicValueAuthorityBlockers = normalized.descriptors.reduce(
    (count, descriptor) => count + [
      descriptor.public_environment_value_authority.bootstrap_static,
      descriptor.public_environment_value_authority.post_measurement_deferred,
    ].filter(({ authority_status }) => authority_status === "required_not_implemented").length,
    0,
  );
  return {
    schema: CVM_LAUNCH_INTENT_RECEIPT_SCHEMA,
    status: "valid",
    truthStatus:
      "canonical_value_free_pre_phala_gate_spec_validated_public_values_unresolved_not_deployment_tdx_or_secret_values",
    cvmLaunchIntentSha256: `sha256:${cvmLaunchIntentCoreDigest(normalized)}`,
    releaseSha: normalized.release_sha,
    chainId: normalized.network.chain_id,
    deploymentIntentSha256: normalized.deployment_intent_sha256,
    contractDeploymentReceiptSha256: normalized.contract_deployment_receipt_sha256,
    topologySha256: normalized.topology_sha256,
    imageReleaseManifestSha256: normalized.image_release_manifest_sha256,
    imageAttestationBundleSha256: normalized.image_attestation_bundle_sha256,
    phalaApiOrigin: normalized.phala_control_plane_authority.api_origin,
    phalaApiVersion: normalized.phala_control_plane_authority.api_version,
    phalaControlPlaneAdapterReady:
      normalized.phala_control_plane_authority.adapter_status === "implemented_and_validated",
    phalaWorkspaceAccountTargetBound: false,
    phalaSdkDebugSecretLoggingGuardComplete: false,
    phalaProvisionRequestFinalAuthorityComplete: false,
    phalaProvisionRequestCandidateCount: Object.keys(
      normalized.phala_provision_request_authority.candidates,
    ).length,
    phalaProvisionRequestListed: normalized.phala_provision_request_authority.listed,
    phalaProvisionRequestKeyProviderMode:
      normalized.phala_provision_request_authority.key_provider_mode,
    cvmResourceProfileEnforcementComplete: false,
    cvmResourceTargetCount: normalized.descriptors.length,
    cvmResourceTargetTotalDiskSizeGb: normalized.descriptors.reduce(
      (total, descriptor) => total + descriptor.launch_settings.cvm_resource_target.disk_size,
      0,
    ),
    cvmResourceTargetAuthorityStatus:
      "reviewed_target_pending_authenticated_catalog_and_quota_probe",
    composeHashAuthorityComplete: false,
    composeHashExpectedCount: normalized.descriptors.length,
    composeHashStagingServerSemanticsEvidenceComplete: false,
    productionExecutionEnabled:
      normalized.sealed_production_execution_policy.availability,
    productionExecutionBlockerCount:
      normalized.sealed_production_execution_policy.blocker_codes.length,
    productionExecutionPolicySha256: phalaProductionExecutionPolicyDigest(
      normalized.sealed_production_execution_policy,
    ),
    descriptorCount: normalized.descriptors.length,
    publicEnvironmentKeyNameCount: publicKeys,
    encryptedSecretEnvironmentKeyNameCount: secretKeys,
    publicEnvironmentValueAuthorityComplete: false,
    publicEnvironmentValueAuthorityBlockerCount: publicValueAuthorityBlockers,
    environmentValueCount: 0,
    postDeploymentIdentityCount: 0,
    reviewMaterialCount: 0,
  };
}

export function createDraftCvmLaunchIntentCore() {
  return {
    schema: CVM_LAUNCH_INTENT_CORE_SCHEMA,
    truth_status: CVM_LAUNCH_TRUTH_STATUS,
    release_sha: null,
    network: { chain_id: BASE_SEPOLIA_CHAIN_ID, name: BASE_SEPOLIA_NAME },
    deployment_intent_sha256: null,
    contract_deployment_receipt_sha256: null,
    topology_sha256: null,
    image_release_manifest_sha256: null,
    image_attestation_bundle_sha256: null,
    phala_control_plane_authority: structuredClone(
      PHALA_CONTROL_PLANE_AUTHORITY,
    ),
    phala_workspace_account_target_authority: structuredClone(
      PHALA_WORKSPACE_ACCOUNT_TARGET_AUTHORITY,
    ),
    phala_sdk_debug_secret_logging_policy: structuredClone(
      PHALA_SDK_DEBUG_SECRET_LOGGING_POLICY,
    ),
    phala_cloud_sdk_wire_transform_authority: structuredClone(
      PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY,
    ),
    phala_provision_request_authority: structuredClone(
      PHALA_PROVISION_REQUEST_AUTHORITY,
    ),
    compose_hash_authority: structuredClone(
      PHALA_DSTACK_COMPOSE_HASH_AUTHORITY,
    ),
    sealed_production_execution_policy: structuredClone(
      PHALA_PRODUCTION_EXECUTION_POLICY,
    ),
    dynamic_runtime_authorities: {
      endpoint_origins: [],
      os_image_hashes: [],
      phala_app_ids: [],
      phala_cvm_ids: [],
      platform_compose_hashes: [],
      qvl_release_policy_hashes: [],
      tee_identities: [],
      verifier_addresses: [],
    },
    descriptors: CVM_LAUNCH_DOMAINS.map((domain) => ({
      trust_domain: domain,
      descriptor_file: CVM_LAUNCH_DESCRIPTOR_POLICY[domain].descriptor_file,
      descriptor_sha256: null,
      descriptor_hash_semantics: "raw_descriptor_bytes_sha256_not_phala_compose_hash",
      launch_settings: structuredClone(CVM_LAUNCH_DESCRIPTOR_POLICY[domain].launch_settings),
      public_environment_key_classification: structuredClone(
        CVM_LAUNCH_DESCRIPTOR_POLICY[domain].public_environment_key_classification,
      ),
      public_environment_value_authority: structuredClone(
        CVM_LAUNCH_DESCRIPTOR_POLICY[domain].public_environment_value_authority,
      ),
      app_compose_candidate: structuredClone(
        CVM_LAUNCH_DESCRIPTOR_POLICY[domain].app_compose_candidate,
      ),
      encrypted_secret_environment_keys_by_phase: structuredClone(
        CVM_LAUNCH_DESCRIPTOR_POLICY[domain].encrypted_secret_environment_keys_by_phase,
      ),
      exact_allowed_environment_keys: [
        ...CVM_LAUNCH_DESCRIPTOR_POLICY[domain].exact_allowed_environment_keys,
      ],
      exact_allowed_environment_keys_sha256:
        CVM_LAUNCH_DESCRIPTOR_POLICY[domain].exact_allowed_environment_keys_sha256,
    })),
  };
}

export function rawSha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function exactLowerHex(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value) || /^0x0+$/.test(value)) {
    throw new Error(`${label} must be a nonzero canonical lowercase hex value`);
  }
  return value;
}

function normalizeFreshBroadcastTransactions(transactions, {
  operatorAddress,
  contractAddresses,
  source = "receipt",
  transactionSpec = FRESH_DEPLOYMENT_TRANSACTION_SPEC,
} = {}) {
  if (!Array.isArray(transactions)
    || transactions.length !== transactionSpec.length) {
    throw new Error("fresh deployment must contain exactly 13 ordered broadcast transactions");
  }
  const ledgerSource = source === "ledger";
  const fields = ledgerSource
    ? [
      "sequence",
      "contractKey",
      "contractName",
      "transactionType",
      "functionSignature",
      "transactionHash",
      "transactionFrom",
      "transactionTo",
      "transactionNonce",
      "transactionInputSha256",
      "receiptStatus",
      "receiptContractAddress",
      "blockNumber",
      "blockHash",
    ]
    : [
      "sequence",
      "contract_key",
      "contract_name",
      "transaction_type",
      "function_signature",
      "transaction_hash",
      "transaction_from",
      "transaction_to",
      "transaction_nonce",
      "transaction_input_sha256",
      "receipt_status",
      "receipt_contract_address",
      "block_number",
      "block_hash",
    ];
  const read = (entry, camel, snake) => entry[ledgerSource ? camel : snake];
  const normalized = transactionSpec.map((spec, index) => {
    const entry = exactRecord(transactions[index], fields, `fresh broadcast transactions[${index}]`);
    const sequence = read(entry, "sequence", "sequence");
    const contractKey = read(entry, "contractKey", "contract_key");
    const contractName = read(entry, "contractName", "contract_name");
    const transactionType = read(entry, "transactionType", "transaction_type");
    const functionSignature = read(entry, "functionSignature", "function_signature");
    const transactionHash = exactLowerHex(
      read(entry, "transactionHash", "transaction_hash"),
      BYTES32,
      `fresh broadcast transactions[${index}] transaction hash`,
    );
    const transactionFrom = exactLowerHex(
      read(entry, "transactionFrom", "transaction_from"),
      ADDRESS,
      `fresh broadcast transactions[${index}] sender`,
    );
    const transactionTo = read(entry, "transactionTo", "transaction_to");
    const transactionNonce = read(entry, "transactionNonce", "transaction_nonce");
    const transactionInputSha256 = normalizedSha256(
      read(entry, "transactionInputSha256", "transaction_input_sha256"),
      `fresh broadcast transactions[${index}] input SHA-256`,
    );
    const receiptStatus = read(entry, "receiptStatus", "receipt_status");
    const receiptContractAddress = read(
      entry,
      "receiptContractAddress",
      "receipt_contract_address",
    );
    const blockNumber = read(entry, "blockNumber", "block_number");
    const blockHash = exactLowerHex(
      read(entry, "blockHash", "block_hash"),
      BYTES32,
      `fresh broadcast transactions[${index}] block hash`,
    );
    if (sequence !== index
      || contractKey !== spec.contract_key
      || contractName !== spec.name
      || transactionType !== spec.transaction_type
      || functionSignature !== spec.function_signature) {
      throw new Error(`fresh broadcast transactions[${index}] does not match the canonical order`);
    }
    if (transactionFrom !== operatorAddress || receiptStatus !== "success") {
      throw new Error(`fresh broadcast transactions[${index}] sender or receipt status mismatch`);
    }
    if (!Number.isSafeInteger(transactionNonce) || transactionNonce < 0) {
      throw new Error(`fresh broadcast transactions[${index}] nonce is invalid`);
    }
    if (!Number.isSafeInteger(blockNumber) || blockNumber < 1) {
      throw new Error(`fresh broadcast transactions[${index}] block number is invalid`);
    }
    const contractAddress = contractAddresses[contractKey];
    if (!contractAddress) {
      throw new Error(`fresh broadcast transactions[${index}] has no canonical contract address`);
    }
    if (transactionType === "CREATE") {
      if (transactionTo !== null || receiptContractAddress !== contractAddress) {
        throw new Error(`fresh broadcast transactions[${index}] CREATE linkage is invalid`);
      }
    } else if (transactionTo !== contractAddress || receiptContractAddress !== null) {
      throw new Error(`fresh broadcast transactions[${index}] CALL linkage is invalid`);
    }
    return {
      sequence: index,
      contract_key: contractKey,
      contract_name: contractName,
      transaction_type: transactionType,
      function_signature: functionSignature,
      transaction_hash: transactionHash,
      transaction_from: transactionFrom,
      transaction_to: transactionTo,
      transaction_nonce: transactionNonce,
      transaction_input_sha256: transactionInputSha256,
      receipt_status: "success",
      receipt_contract_address: receiptContractAddress,
      block_number: blockNumber,
      block_hash: blockHash,
    };
  });
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index].transaction_nonce !== normalized[index - 1].transaction_nonce + 1) {
      throw new Error("fresh broadcast transaction nonces must be exact and consecutive");
    }
  }
  if (new Set(normalized.map(({ transaction_hash }) => transaction_hash)).size
      !== normalized.length) {
    throw new Error("fresh broadcast transaction hashes must be pairwise distinct");
  }
  return normalized;
}

export function freshBroadcastTransactionEvidenceFromLedger(
  transactions,
  { operatorAddress, contractAddresses } = {},
) {
  const normalizedOperatorAddress = exactLowerHex(
    operatorAddress,
    ADDRESS,
    "fresh broadcast evidence operator address",
  );
  if (!isRecord(contractAddresses)) {
    throw new Error("fresh broadcast evidence contract addresses must be an object");
  }
  const normalized = normalizeFreshBroadcastTransactions(transactions, {
    operatorAddress: normalizedOperatorAddress,
    contractAddresses,
    source: "ledger",
  });
  return {
    broadcast_transactions_sha256: rawSha256(
      Buffer.from(JSON.stringify(sortedObject(normalized)), "utf8"),
    ),
    broadcast_transactions: normalized,
  };
}

export function projectFreshContractDeploymentReceipt(ledger, {
  releaseSha: expectedReleaseSha,
  expectedDeploymentIntentSha256,
  expectedReviewerAuthorityGenesisAcceptanceSha256,
  expectedTinkerAccountBindingCeremonyReceiptSha256,
} = {}) {
  const value = isRecord(ledger) ? ledger : (() => { throw new Error("contract ledger must be an object"); })();
  if (value.schemaVersion !== 2) throw new Error("contract ledger schemaVersion must be 2");
  if (Object.hasOwn(value, "notAuthorityForFreshRelease")
    || Object.hasOwn(value, "supersededBoundary")) {
    throw new Error("contract ledger contains a legacy non-authority marker");
  }
  if (value.status !== "fresh_contract_suite_deployed_pending_cvm_binding") {
    throw new Error("contract ledger status is not the fresh fail-closed contract suite");
  }
  const network = exactRecord(value.network, [
    "chainId",
    "explorerBaseUrl",
    "name",
    "rpcEnv",
  ], "contract ledger network");
  if (network.chainId !== BASE_SEPOLIA_CHAIN_ID
    || network.name !== "Base Sepolia"
    || network.rpcEnv !== "BASE_SEPOLIA_RPC_URL"
    || network.explorerBaseUrl !== "https://sepolia.basescan.org") {
    throw new Error("contract ledger network is not the canonical Base Sepolia descriptor");
  }
  const release = normalizedReleaseSha(expectedReleaseSha, "expected release SHA");
  const intent = normalizedSha256(
    expectedDeploymentIntentSha256,
    "expected deployment intent SHA-256",
  );
  const reviewerAuthorityGenesisAcceptance = normalizedSha256(
    expectedReviewerAuthorityGenesisAcceptanceSha256,
    "expected reviewer authority genesis acceptance SHA-256",
  );
  const tinkerAccountBindingCeremonyReceiptSha256 = normalizedSha256(
    expectedTinkerAccountBindingCeremonyReceiptSha256,
    "expected Tinker account-binding ceremony receipt SHA-256",
  );
  const operator = isRecord(value.currentOperatorDeployer)
    ? value.currentOperatorDeployer
    : (() => { throw new Error("contract ledger currentOperatorDeployer is missing"); })();
  const operatorAddress = exactLowerHex(
    operator.address,
    ADDRESS,
    "currentOperatorDeployer.address",
  );
  if (operator.keystoreAccount !== "dev" || operator.privateKeyMaterial !== "not_used") {
    throw new Error("contract ledger must record encrypted dev keystore deployment without raw key material");
  }
  const fresh = isRecord(value.freshDeployment)
    ? value.freshDeployment
    : (() => { throw new Error("contract ledger freshDeployment is missing"); })();
  const suite = isRecord(fresh.contractSuite)
    ? fresh.contractSuite
    : (() => { throw new Error("contract ledger freshDeployment.contractSuite is missing"); })();
  if (suite.status !== "broadcast_complete_pending_cvm_binding"
    || suite.sourceCommit !== release
    || suite.deploymentIntentSha256 !== intent
    || suite.reviewerAuthorityGenesisAcceptanceSha256
      !== reviewerAuthorityGenesisAcceptance
    || suite.tinkerAccountBindingCeremonyReceiptSha256
      !== tinkerAccountBindingCeremonyReceiptSha256
    || suite.keystoreAccount !== "dev"
    || suite.runtimeCodeProof !== "exact_creation_reexecution_match_all_contracts"
    || suite.exactCreationInputProof !== FRESH_CONTRACT_CREATION_INPUT_PROOF
    || suite.broadcastTransactionProof !== FRESH_CONTRACT_BROADCAST_PROOF
    || suite.broadcastTransactionCount !== FRESH_DEPLOYMENT_TRANSACTION_SPEC.length) {
    throw new Error("contract ledger does not contain the exact fresh fail-closed suite deployment");
  }
  const matchingHistoryEntries = Array.isArray(value.deploymentHistory)
    ? value.deploymentHistory.filter((entry) => (
      entry?.kind === "fresh_reviewed_scope_contract_suite"
      && entry.sourceCommit === release
      && entry.deploymentIntentSha256 === intent
      && entry.reviewerAuthorityGenesisAcceptanceSha256
        === reviewerAuthorityGenesisAcceptance
    ))
    : [];
  if (matchingHistoryEntries.length !== 1) {
    throw new Error(
      "contract ledger must contain exactly one matching append-only fresh-suite history record",
    );
  }
  const [matchingHistory] = matchingHistoryEntries;
  if (matchingHistory.tinkerAccountBindingCeremonyReceiptSha256
      !== tinkerAccountBindingCeremonyReceiptSha256) {
    throw new Error(
      "contract ledger fresh-suite history does not bind the expected Tinker account-binding ceremony receipt",
    );
  }
  const contracts = isRecord(value.contracts)
    ? value.contracts
    : (() => { throw new Error("contract ledger contracts are missing"); })();
  const actualContractKeys = Object.keys(contracts).sort();
  const exactContractKeys = CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS
    .map(({ ledger_key }) => ledger_key)
    .sort();
  if (JSON.stringify(actualContractKeys) !== JSON.stringify(exactContractKeys)) {
    throw new Error("contract ledger must contain exactly the canonical seven-contract scope");
  }
  const projectedContracts = CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ ledger_key, name }) => {
      const entry = isRecord(contracts[ledger_key])
        ? contracts[ledger_key]
        : (() => { throw new Error(`contract ledger ${ledger_key} must be an object`); })();
      if (entry.sourceCommit !== release) {
        throw new Error(`contract ledger ${ledger_key} is not from the launch release`);
      }
      const deploymentBlock = entry.deploymentBlock;
      if (!Number.isSafeInteger(deploymentBlock) || deploymentBlock < 1) {
        throw new Error(`contract ledger ${ledger_key}.deploymentBlock is invalid`);
      }
      if (entry.deploymentReceiptStatus !== "success") {
        throw new Error(`contract ledger ${ledger_key}.deploymentReceiptStatus must be success`);
      }
      if (entry.deploymentTxFrom !== operatorAddress
        || entry.deploymentReceiptContractAddress !== entry.address) {
        throw new Error(`contract ledger ${ledger_key} transaction sender or receipt contract address mismatch`);
      }
      if (ledger_key === "challengeRegistry") {
        if ((Object.hasOwn(entry, "status")
            && entry.status !== "deployed_empty_active_registry")
          || (Object.hasOwn(entry, "owner") && entry.owner !== operatorAddress)
          || (Object.hasOwn(entry, "registryPaused") && entry.registryPaused !== false)
          || (Object.hasOwn(entry, "challengeCount") && entry.challengeCount !== 0)
          || (Object.hasOwn(entry, "nextChallengeId") && entry.nextChallengeId !== 1)) {
          throw new Error("contract ledger ChallengeRegistry is not the pristine active fresh registry");
        }
      }
      const projected = {
        name,
        address: exactLowerHex(entry.address, ADDRESS, `${ledger_key}.address`),
        runtime_code_hash: exactLowerHex(
          entry.runtimeCodeHash,
          BYTES32,
          `${ledger_key}.runtimeCodeHash`,
        ),
        deployment_tx_hash: exactLowerHex(
          entry.deploymentTx,
          BYTES32,
          `${ledger_key}.deploymentTx`,
        ),
        deployment_block: deploymentBlock,
        deployment_block_hash: exactLowerHex(
          entry.deploymentBlockHash,
          BYTES32,
          `${ledger_key}.deploymentBlockHash`,
        ),
        creation_input_sha256: normalizedSha256(
          entry.creationInputSha256,
          `${ledger_key}.creationInputSha256`,
        ),
        receipt_status: "success",
      };
      if (ledger_key === "executionPolicyAnchor") {
        const deploymentIntentBytes32 = `0x${intent.slice("sha256:".length)}`;
        const reviewerAuthorityGenesisAcceptanceBytes32 =
          `0x${reviewerAuthorityGenesisAcceptance.slice("sha256:".length)}`;
        if (entry.deploymentIntentSha256Bytes32 !== deploymentIntentBytes32
          || entry.reviewerAuthorityGenesisAcceptanceSha256Bytes32
            !== reviewerAuthorityGenesisAcceptanceBytes32
          || entry.authorityCommitmentReadProof
            !== FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF
          || entry.authorityCommitmentReadBlock !== deploymentBlock
          || entry.authorityCommitmentReadBlockHash !== entry.deploymentBlockHash) {
          throw new Error(
            "contract ledger ExecutionPolicyAnchor authority commitments are not exact dual-RPC deployment-block evidence",
          );
        }
        projected.deployment_intent_sha256_bytes32 = deploymentIntentBytes32;
        projected.reviewer_authority_genesis_acceptance_sha256_bytes32 =
          reviewerAuthorityGenesisAcceptanceBytes32;
        projected.authority_commitment_read_proof =
          FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF;
        projected.authority_commitment_read_block = deploymentBlock;
        projected.authority_commitment_read_block_hash = exactLowerHex(
          entry.authorityCommitmentReadBlockHash,
          BYTES32,
          "executionPolicyAnchor.authorityCommitmentReadBlockHash",
        );
      }
      return projected;
    });
  if (new Set(projectedContracts.map(({ address }) => address)).size
      !== projectedContracts.length
    || new Set(projectedContracts.map(({ deployment_tx_hash }) => deployment_tx_hash)).size
      !== projectedContracts.length) {
    throw new Error("fresh contract suite addresses and deployment transactions must be pairwise distinct");
  }
  const contractAddresses = Object.fromEntries(
    CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ ledger_key, name }) => [
      ledger_key,
      projectedContracts.find((entry) => entry.name === name)?.address,
    ]),
  );
  const broadcastTransactions = normalizeFreshBroadcastTransactions(
    suite.broadcastTransactions,
    { operatorAddress, contractAddresses, source: "ledger" },
  );
  for (const contract of projectedContracts) {
    const { ledger_key: contractKey } = CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.find(
      ({ name }) => name === contract.name,
    );
    const create = broadcastTransactions.find((entry) => (
      entry.contract_key === contractKey && entry.transaction_type === "CREATE"
    ));
    if (!create
      || create.transaction_hash !== contract.deployment_tx_hash
      || create.block_number !== contract.deployment_block
      || create.block_hash !== contract.deployment_block_hash
      || create.transaction_input_sha256 !== contract.creation_input_sha256) {
      throw new Error(`fresh contract ${contract.name} is not linked to its exact CREATE evidence`);
    }
  }
  const broadcastTransactionsSha256 = rawSha256(
    Buffer.from(JSON.stringify(sortedObject(broadcastTransactions)), "utf8"),
  );
  if (suite.broadcastTransactionsSha256 !== broadcastTransactionsSha256
    || matchingHistory.broadcastTransactionsSha256 !== broadcastTransactionsSha256) {
    throw new Error("fresh deployment ordered broadcast transaction digest mismatch");
  }
  return {
    schema: FRESH_CONTRACT_DEPLOYMENT_RECEIPT_SCHEMA,
    network: { chain_id: BASE_SEPOLIA_CHAIN_ID, name: BASE_SEPOLIA_NAME },
    release_sha: release,
    deployment_intent_sha256: intent,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerAuthorityGenesisAcceptance,
    tinker_account_binding_ceremony_receipt_sha256:
      tinkerAccountBindingCeremonyReceiptSha256,
    operator_address: operatorAddress,
    keystore_account: "dev",
    exact_creation_proof: FRESH_CONTRACT_CREATION_INPUT_PROOF,
    broadcast_transaction_proof: FRESH_CONTRACT_BROADCAST_PROOF,
    broadcast_transactions_sha256: broadcastTransactionsSha256,
    broadcast_transactions: broadcastTransactions,
    contracts: projectedContracts,
  };
}

export function normalizeFreshContractDeploymentReceipt(receipt, {
  expectedDeploymentIntentSha256,
  expectedReviewerAuthorityGenesisAcceptanceSha256,
  expectedTinkerAccountBindingCeremonyReceiptSha256,
} = {}) {
  return normalizeFreshContractDeploymentReceiptVersion(receipt, {
    expectedDeploymentIntentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256,
    expectedTinkerAccountBindingCeremonyReceiptSha256,
  }, {
    schema: FRESH_CONTRACT_DEPLOYMENT_RECEIPT_SCHEMA,
    includeTinkerAccountBindingCeremonyReceipt: true,
  });
}

export function normalizeHistoricalFreshContractDeploymentReceiptV3(receipt, {
  expectedDeploymentIntentSha256,
  expectedReviewerAuthorityGenesisAcceptanceSha256,
} = {}) {
  return normalizeFreshContractDeploymentReceiptVersion(receipt, {
    expectedDeploymentIntentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256,
  }, {
    schema: FRESH_CONTRACT_DEPLOYMENT_RECEIPT_V3_SCHEMA,
    includeTinkerAccountBindingCeremonyReceipt: false,
    transactionSpec: FRESH_DEPLOYMENT_TRANSACTION_SPEC_V3,
  });
}

function normalizeFreshContractDeploymentReceiptVersion(receipt, {
  expectedDeploymentIntentSha256,
  expectedReviewerAuthorityGenesisAcceptanceSha256,
  expectedTinkerAccountBindingCeremonyReceiptSha256,
}, {
  schema,
  includeTinkerAccountBindingCeremonyReceipt,
  transactionSpec = FRESH_DEPLOYMENT_TRANSACTION_SPEC,
}) {
  const receiptFields = [
    "schema",
    "network",
    "release_sha",
    "deployment_intent_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "operator_address",
    "keystore_account",
    "exact_creation_proof",
    "broadcast_transaction_proof",
    "broadcast_transactions_sha256",
    "broadcast_transactions",
    "contracts",
  ];
  if (includeTinkerAccountBindingCeremonyReceipt) {
    receiptFields.push("tinker_account_binding_ceremony_receipt_sha256");
  }
  const parsed = exactRecord(receipt, [
    ...receiptFields,
  ], "fresh contract deployment receipt");
  if (parsed.schema !== schema) {
    throw new Error("contract deployment receipt schema mismatch");
  }
  const network = exactRecord(parsed.network, ["chain_id", "name"], "fresh receipt network");
  if (network.chain_id !== BASE_SEPOLIA_CHAIN_ID || network.name !== BASE_SEPOLIA_NAME) {
    throw new Error("fresh receipt network must be Base Sepolia");
  }
  if (parsed.keystore_account !== "dev"
    || parsed.exact_creation_proof !== FRESH_CONTRACT_CREATION_INPUT_PROOF
    || parsed.broadcast_transaction_proof !== FRESH_CONTRACT_BROADCAST_PROOF) {
    throw new Error("fresh receipt keystore or exact-creation proof mismatch");
  }
  const deploymentIntentSha256 = normalizedSha256(
    expectedDeploymentIntentSha256,
    "expected fresh receipt deployment intent SHA-256",
  );
  const reviewerAuthorityGenesisAcceptanceSha256 = normalizedSha256(
    expectedReviewerAuthorityGenesisAcceptanceSha256,
    "expected fresh receipt reviewer authority genesis acceptance SHA-256",
  );
  const tinkerAccountBindingCeremonyReceiptSha256 =
    includeTinkerAccountBindingCeremonyReceipt
      ? normalizedSha256(
        expectedTinkerAccountBindingCeremonyReceiptSha256,
        "expected fresh receipt Tinker account-binding ceremony receipt SHA-256",
      )
      : null;
  if (parsed.deployment_intent_sha256 !== deploymentIntentSha256
    || parsed.reviewer_authority_genesis_acceptance_sha256
      !== reviewerAuthorityGenesisAcceptanceSha256
    || (includeTinkerAccountBindingCeremonyReceipt
      && parsed.tinker_account_binding_ceremony_receipt_sha256
        !== tinkerAccountBindingCeremonyReceiptSha256)) {
    throw new Error("fresh receipt authority commitments do not match the external reviewed pins");
  }
  if (!Array.isArray(parsed.contracts)
    || parsed.contracts.length !== CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.length) {
    throw new Error("fresh receipt must contain exactly seven contract results");
  }
  const contracts = CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ name }, index) => {
    const contractFields = [
      "name",
      "address",
      "runtime_code_hash",
      "deployment_tx_hash",
      "deployment_block",
      "deployment_block_hash",
      "creation_input_sha256",
      "receipt_status",
    ];
    if (name === "ExecutionPolicyAnchor") {
      contractFields.push(
        "authority_commitment_read_block",
        "authority_commitment_read_block_hash",
        "authority_commitment_read_proof",
        "deployment_intent_sha256_bytes32",
        "reviewer_authority_genesis_acceptance_sha256_bytes32",
      );
    }
    const entry = exactRecord(
      parsed.contracts[index],
      contractFields,
      `fresh receipt contracts[${index}]`,
    );
    if (entry.name !== name || entry.receipt_status !== "success") {
      throw new Error(`fresh receipt contracts[${index}] name or receipt status mismatch`);
    }
    if (!Number.isSafeInteger(entry.deployment_block) || entry.deployment_block < 1) {
      throw new Error(`fresh receipt contracts[${index}].deployment_block is invalid`);
    }
    const normalized = {
      name,
      address: exactLowerHex(entry.address, ADDRESS, `fresh receipt ${name} address`),
      runtime_code_hash: exactLowerHex(
        entry.runtime_code_hash,
        BYTES32,
        `fresh receipt ${name} runtime code hash`,
      ),
      deployment_tx_hash: exactLowerHex(
        entry.deployment_tx_hash,
        BYTES32,
        `fresh receipt ${name} deployment transaction hash`,
      ),
      deployment_block: entry.deployment_block,
      deployment_block_hash: exactLowerHex(
        entry.deployment_block_hash,
        BYTES32,
        `fresh receipt ${name} deployment block hash`,
      ),
      creation_input_sha256: normalizedSha256(
        entry.creation_input_sha256,
        `fresh receipt ${name} creation input SHA-256`,
      ),
      receipt_status: "success",
    };
    if (name === "ExecutionPolicyAnchor") {
      const deploymentIntentBytes32 =
        `0x${deploymentIntentSha256.slice("sha256:".length)}`;
      const reviewerAuthorityGenesisAcceptanceBytes32 =
        `0x${reviewerAuthorityGenesisAcceptanceSha256.slice("sha256:".length)}`;
      if (entry.deployment_intent_sha256_bytes32 !== deploymentIntentBytes32
        || entry.reviewer_authority_genesis_acceptance_sha256_bytes32
          !== reviewerAuthorityGenesisAcceptanceBytes32
        || entry.authority_commitment_read_proof
          !== FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF
        || entry.authority_commitment_read_block !== entry.deployment_block
        || entry.authority_commitment_read_block_hash
          !== entry.deployment_block_hash) {
        throw new Error(
          "fresh receipt ExecutionPolicyAnchor authority commitment evidence mismatch",
        );
      }
      normalized.deployment_intent_sha256_bytes32 = deploymentIntentBytes32;
      normalized.reviewer_authority_genesis_acceptance_sha256_bytes32 =
        reviewerAuthorityGenesisAcceptanceBytes32;
      normalized.authority_commitment_read_proof =
        FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF;
      normalized.authority_commitment_read_block = entry.deployment_block;
      normalized.authority_commitment_read_block_hash = exactLowerHex(
        entry.authority_commitment_read_block_hash,
        BYTES32,
        "fresh receipt ExecutionPolicyAnchor authority commitment read block hash",
      );
    }
    return normalized;
  });
  if (new Set(contracts.map(({ address }) => address)).size !== contracts.length
    || new Set(contracts.map(({ deployment_tx_hash }) => deployment_tx_hash)).size
      !== contracts.length) {
    throw new Error("fresh receipt contract addresses and deployment transactions must be pairwise distinct");
  }
  const contractAddresses = Object.fromEntries(
    CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ ledger_key, name }) => [
      ledger_key,
      contracts.find((entry) => entry.name === name)?.address,
    ]),
  );
  const operatorAddress = exactLowerHex(
    parsed.operator_address,
    ADDRESS,
    "fresh receipt operator_address",
  );
  const broadcastTransactions = normalizeFreshBroadcastTransactions(
    parsed.broadcast_transactions,
    { operatorAddress, contractAddresses, transactionSpec },
  );
  const broadcastTransactionsSha256 = rawSha256(
    Buffer.from(JSON.stringify(sortedObject(broadcastTransactions)), "utf8"),
  );
  if (parsed.broadcast_transactions_sha256 !== broadcastTransactionsSha256) {
    throw new Error("fresh receipt broadcast transaction SHA-256 mismatch");
  }
  for (const contract of contracts) {
    const { ledger_key: contractKey } = CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.find(
      ({ name }) => name === contract.name,
    );
    const create = broadcastTransactions.find((entry) => (
      entry.contract_key === contractKey && entry.transaction_type === "CREATE"
    ));
    if (!create
      || create.transaction_hash !== contract.deployment_tx_hash
      || create.block_number !== contract.deployment_block
      || create.block_hash !== contract.deployment_block_hash
      || create.transaction_input_sha256 !== contract.creation_input_sha256) {
      throw new Error(`fresh receipt ${contract.name} CREATE evidence mismatch`);
    }
  }
  const normalizedReceipt = {
    schema,
    network: { chain_id: BASE_SEPOLIA_CHAIN_ID, name: BASE_SEPOLIA_NAME },
    release_sha: normalizedReleaseSha(parsed.release_sha, "fresh receipt release_sha"),
    deployment_intent_sha256: deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerAuthorityGenesisAcceptanceSha256,
    operator_address: operatorAddress,
    keystore_account: "dev",
    exact_creation_proof: FRESH_CONTRACT_CREATION_INPUT_PROOF,
    broadcast_transaction_proof: FRESH_CONTRACT_BROADCAST_PROOF,
    broadcast_transactions_sha256: broadcastTransactionsSha256,
    broadcast_transactions: broadcastTransactions,
    contracts,
  };
  if (includeTinkerAccountBindingCeremonyReceipt) {
    normalizedReceipt.tinker_account_binding_ceremony_receipt_sha256 =
      tinkerAccountBindingCeremonyReceiptSha256;
  }
  return normalizedReceipt;
}

export function freshContractDeploymentReceiptDigest(receipt, authorityPins) {
  const normalized = normalizeFreshContractDeploymentReceipt(receipt, authorityPins);
  return createHash("sha256")
    .update(Buffer.from(FRESH_CONTRACT_DEPLOYMENT_RECEIPT_DOMAIN, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(normalized)), "utf8"))
    .digest("hex");
}

export function historicalFreshContractDeploymentReceiptV3Digest(
  receipt,
  authorityPins,
) {
  const normalized = normalizeHistoricalFreshContractDeploymentReceiptV3(
    receipt,
    authorityPins,
  );
  return createHash("sha256")
    .update(Buffer.from(FRESH_CONTRACT_DEPLOYMENT_RECEIPT_V3_DOMAIN, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(normalized)), "utf8"))
    .digest("hex");
}

export function canonicalFreshContractDeploymentReceiptText(receipt, authorityPins) {
  return `${JSON.stringify(
    sortedObject(normalizeFreshContractDeploymentReceipt(receipt, authorityPins)),
    null,
    2,
  )}\n`;
}

export function canonicalHistoricalFreshContractDeploymentReceiptV3Text(
  receipt,
  authorityPins,
) {
  return `${JSON.stringify(
    sortedObject(normalizeHistoricalFreshContractDeploymentReceiptV3(
      receipt,
      authorityPins,
    )),
    null,
    2,
  )}\n`;
}

export function bareSha256(value, label) {
  if (typeof value !== "string"
    || !BARE_SHA256.test(value)
    || value === "0".repeat(64)) {
    throw new Error(`${label} must be a nonzero bare lowercase SHA-256 digest`);
  }
  return value;
}

export function releaseSha(value, label) {
  return normalizedReleaseSha(value, label);
}
