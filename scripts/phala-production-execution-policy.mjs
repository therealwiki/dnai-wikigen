/**
 * Canonical public policy for the exact production Phala bootstrap executor.
 *
 * Bootstrap execution is available only through the reviewed runtime. Later
 * post-measurement and live-activation stages remain separately authorized and
 * their blockers must never be interpreted as bootstrap transport blockers.
 */

export const PHALA_PRODUCTION_EXECUTION_POLICY_SCHEMA =
  "dnai.phala-production-execution-policy.v1";
export const PHALA_PRODUCTION_EXECUTION_DISABLED_CODE =
  "phala_production_execution_disabled";
export const PHALA_PRODUCTION_EXECUTION_AVAILABLE_CODE =
  "exact_production_executor_available";
export const PHALA_PINNED_SDK_WIRE_TRANSFORM_PROOF_MISSING =
  "pinned_phala_sdk_wire_transform_and_capture_proof_required";
export const PHALA_RELEASE_MANIFEST_SIGSTORE_VERIFICATION_MISSING =
  "release_manifest_sigstore_bundle_not_cryptographically_verified";
export const PHALA_REVIEWER_GENESIS_ACCEPTANCE_MISSING =
  "reviewer_genesis_acceptance_not_cryptographically_verified";
export const PHALA_REVIEWER_GENESIS_ANCHOR_MISSING =
  "reviewer_genesis_not_independently_anchored";
export const PHALA_CRYPTOGRAPHIC_BOOTSTRAP_AUTHORITY_MISSING =
  "cryptographically_anchored_non_live_bootstrap_authorization_required";
export const PHALA_CEREMONY_AUTHORIZATION_MISSING =
  "cryptographically_reviewed_ceremony_authorization_required";
export const PHALA_LIVE_ACTIVATION_AUTHORITY_MISSING =
  "separately_reviewed_live_activation_authority_required";
export const PHALA_PRODUCTION_BOOTSTRAP_IMPLEMENTED_CONTROL_CODES = Object.freeze([
  "sealed_canonical_readiness_collector_required",
  "pinned_phala_api_origin_and_version_adapter_required",
  "reviewed_phala_workspace_account_target_required",
  "phala_sdk_debug_secret_logging_guard_required",
  PHALA_RELEASE_MANIFEST_SIGSTORE_VERIFICATION_MISSING,
  "authenticated_phala_os_catalog_adapter_required",
  "independent_app_env_pubkey_binding_adapter_required",
  "reviewed_phala_kms_k256_identity_catalog_pin_required",
  "signed_app_env_pubkey_cryptographic_verification_adapter_required",
  "pinned_phala_sdk_adapter_required",
  PHALA_PINNED_SDK_WIRE_TRANSFORM_PROOF_MISSING,
  "pinned_dstack_compose_hash_adapter_required",
  "staging_provision_compose_hash_semantics_evidence_required",
  "authenticated_cvm_resource_catalog_and_quota_evidence_required",
  "explicit_cvm_resource_profile_enforcement_required",
  "durable_recovery_journal_directory_fsync_and_full_write_required",
  "static_public_environment_authority_projection_required",
  PHALA_REVIEWER_GENESIS_ACCEPTANCE_MISSING,
  PHALA_REVIEWER_GENESIS_ANCHOR_MISSING,
  PHALA_CRYPTOGRAPHIC_BOOTSTRAP_AUTHORITY_MISSING,
]);
export const PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES = Object.freeze([]);
export const PHALA_PRODUCTION_POST_MEASUREMENT_BLOCKER_CODES = Object.freeze([
  "deferred_public_environment_final_authority_projection_required",
  PHALA_CEREMONY_AUTHORIZATION_MISSING,
]);
export const PHALA_PRODUCTION_LIVE_ACTIVATION_BLOCKER_CODES = Object.freeze([
  PHALA_LIVE_ACTIVATION_AUTHORITY_MISSING,
]);
export const PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES = Object.freeze([
  ...PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
]);

export const PHALA_PRODUCTION_EXECUTION_POLICY = Object.freeze({
  schema: PHALA_PRODUCTION_EXECUTION_POLICY_SCHEMA,
  availability: true,
  reason_code: null,
  blocker_codes: PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
  caller_supplied_callbacks_accepted: false,
  caller_supplied_clients_accepted: false,
  manual_cli_or_sdk_bypass_authorized: false,
});
