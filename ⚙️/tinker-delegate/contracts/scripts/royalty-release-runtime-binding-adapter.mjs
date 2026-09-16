import { createHash } from "node:crypto";

import {
  finalReleaseAuthorityCoreDigest,
} from "../../../../scripts/execution-policy-release-core.mjs";
import {
  REQUIRED_ROYALTY_SETTLEMENT_RELEASE_BINDING_SCHEMA,
  ROYALTY_SETTLEMENT_RELEASE_BINDING_DOMAIN,
  normalizeCurrentFinalReleaseAuthorityV4,
  normalizeRoyaltySettlementReleaseBinding,
  normalizeRoyaltySettlementReleaseReconciliationReceipt,
  royaltySettlementReleaseBindingSha256,
} from "./royalty-release-phase-plan.mjs";

export const ROYALTY_RUNTIME_BINDING_ADAPTER_SCHEMA =
  "dnai.royalty-settlement-runtime-binding-adapter.v1";
export const ROYALTY_RUNTIME_BINDING_ADAPTER_STATUS =
  "exact_js_final_binding_to_python_runtime_binding";
export const ROYALTY_RUNTIME_BINDING_ADAPTER_TRUTH_STATUS =
  "deterministic_cross_language_projection_not_runtime_startup_or_chain_evidence";
export const ROYALTY_RUNTIME_BINDING_ADAPTER_DOMAIN =
  "dnai-wikigen/royalty-settlement-runtime-binding-adapter/v1\0";
export const PYTHON_ROYALTY_RUNTIME_BINDING_DOMAIN =
  "dnai-wikigen/collaboration-royalty-release-binding/v1\0";
export const ROYALTY_QVL_POLICY_DOMAIN =
  "dnai-wikigen/royalty-settlement-qvl-policy/v2\0";

const ROYALTY_QVL_POLICY_SCHEMA = "dnai.royalty-settlement-qvl-policy.v2";
const ROYALTY_QVL_AUTHORIZATION_SCHEMA =
  "dnai.royalty-settlement-qvl-authorization-request.v2";
const ROYALTY_QVL_BINDING_KIND = "royalty_settlement_qvl_v2";
const SOURCE_BINDING_FIELDS = Object.freeze([
  "deployment_intent_sha256",
  "final_release_authority_v4_sha256",
  "release_sha",
  "royalty_release_active_state_sha256",
  "royalty_release_authority",
  "royalty_release_history_receipt_sha256",
  "royalty_release_history_sha256",
  "royalty_settlement_release_binding_template",
  "schema",
]);

function fail(message) {
  throw new TypeError(message);
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

function canonicalCompactText(value) {
  return JSON.stringify(sorted(value));
}

function canonicalArtifactText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function digest(prefix, value, { compact = false, bytes32 = false } = {}) {
  const hex = createHash("sha256")
    .update(prefix, "utf8")
    .update(compact ? canonicalCompactText(value) : canonicalArtifactText(value), "utf8")
    .digest("hex");
  return `${bytes32 ? "0x" : "sha256:"}${hex}`;
}

function qvlBinding(runtimeBinding, template) {
  return {
    kind: ROYALTY_QVL_BINDING_KIND,
    distributor_address: runtimeBinding.distributor_address,
    distributor_runtime_code_hash:
      runtimeBinding.distributor_runtime_code_hash,
    owner: runtimeBinding.owner_address,
    settlement_verifier: runtimeBinding.settlement_verifier_address,
    settlement_verifier_key_path: template.settlement_verifier_key_path,
    settlement_verifier_custody: template.settlement_verifier_custody,
    execution_policy_anchor: runtimeBinding.execution_policy_anchor_address,
    anchor_writer_release_commitment:
      runtimeBinding.anchor_writer_release_commitment,
    release_policy_commitment: runtimeBinding.release_policy_commitment,
    authority_nonce: String(runtimeBinding.authority_nonce),
    qvl_signer_key_id: runtimeBinding.royalty_qvl_signer_key_id,
    main_runtime_cvm_id: runtimeBinding.main_runtime_cvm_id,
    deployment_intent_sha256: runtimeBinding.deployment_intent_sha256,
    release_authority_sha256: runtimeBinding.release_authority_sha256,
    measurement_policy_sha256: runtimeBinding.measurement_policy_sha256,
    max_authorization_lifetime_seconds:
      runtimeBinding.max_authorization_lifetime_seconds,
  };
}

export function royaltyRuntimeQvlPolicyCommitment(runtimeBinding, template) {
  return digest(ROYALTY_QVL_POLICY_DOMAIN, {
    schema: ROYALTY_QVL_POLICY_SCHEMA,
    authorization_schema: ROYALTY_QVL_AUTHORIZATION_SCHEMA,
    qvl_release_policy_hash: runtimeBinding.qvl_release_policy_hash,
    chain_id: runtimeBinding.chain_id,
    compose_hash: runtimeBinding.compose_hash,
    app_id: runtimeBinding.app_id,
    os_image_hash: runtimeBinding.os_image_hash,
    royalty_qvl_verifier: runtimeBinding.royalty_qvl_verifier_address,
    binding: qvlBinding(runtimeBinding, template),
  }, { compact: true, bytes32: true });
}

export function pythonRoyaltyRuntimeBindingCommitment(runtimeBinding) {
  exactRecord(runtimeBinding, [
    "anchor_writer_release_commitment",
    "app_id",
    "authority_nonce",
    "ceremony_nonce",
    "chain_id",
    "compose_hash",
    "deployment_intent_sha256",
    "distributor_address",
    "distributor_runtime_code_hash",
    "execution_policy_anchor_address",
    "main_runtime_cvm_id",
    "max_authorization_lifetime_seconds",
    "measurement_policy_sha256",
    "os_image_hash",
    "owner_address",
    "qvl_release_policy_hash",
    "release_authority_sha256",
    "release_policy_commitment",
    "royalty_qvl_policy_commitment",
    "royalty_qvl_signer_key_id",
    "royalty_qvl_verifier_address",
    "settlement_verifier_address",
  ], "Python Royalty runtime binding");
  return digest(PYTHON_ROYALTY_RUNTIME_BINDING_DOMAIN, runtimeBinding, {
    compact: true,
  });
}

export function projectRoyaltyRuntimeBindingAdapter({
  finalReleaseAuthorityV4,
  reconciliationReceipt,
  royaltySettlementReleaseBinding,
}) {
  const finalAuthority = normalizeCurrentFinalReleaseAuthorityV4(
    finalReleaseAuthorityV4,
  );
  const sourceBinding = normalizeRoyaltySettlementReleaseBinding(
    royaltySettlementReleaseBinding,
    { finalReleaseAuthorityV4: finalAuthority },
  );
  const reconciliation =
    normalizeRoyaltySettlementReleaseReconciliationReceipt(
      reconciliationReceipt,
    );
  const sourceBindingSha256 = royaltySettlementReleaseBindingSha256(
    sourceBinding,
    { finalReleaseAuthorityV4: finalAuthority },
  );
  const finalAuthoritySha256 =
    `sha256:${finalReleaseAuthorityCoreDigest(finalAuthority)}`;
  if (reconciliation.release_sha !== finalAuthority.release_sha
    || reconciliation.deployment_intent_sha256
      !== finalAuthority.deployment_intent_sha256
    || reconciliation.final_release_authority_v4_sha256
      !== finalAuthoritySha256
    || reconciliation.royalty_release_history_receipt_sha256
      !== sourceBinding.royalty_release_history_receipt_sha256
    || reconciliation.royalty_release_history_sha256
      !== sourceBinding.royalty_release_history_sha256
    || reconciliation.royalty_settlement_release_binding_sha256
      !== sourceBindingSha256) {
    fail("runtime adapter requires the exact reconciled final-authority v4, H, and source binding");
  }

  const authority = finalAuthority.royalty_release_authority;
  const template = finalAuthority.royalty_settlement_release_binding_template;
  const runtimeWithoutQvlCommitment = {
    distributor_address: authority.distributor_address,
    distributor_runtime_code_hash: template.distributor_runtime_code_hash,
    owner_address: authority.owner,
    authority_nonce: authority.authority_nonce,
    settlement_verifier_address: authority.settlement_verifier,
    royalty_qvl_verifier_address: authority.qvl_verifier,
    execution_policy_anchor_address: authority.execution_policy_anchor,
    anchor_writer_release_commitment:
      authority.anchor_writer_release_commitment,
    release_policy_commitment: authority.release_policy_commitment,
    royalty_qvl_signer_key_id: template.royalty_qvl_signer_key_id,
    qvl_release_policy_hash: template.qvl_release_policy_hash,
    main_runtime_cvm_id: template.main_runtime_cvm_id,
    deployment_intent_sha256: finalAuthority.deployment_intent_sha256,
    release_authority_sha256: finalAuthoritySha256,
    ceremony_nonce: template.ceremony_nonce,
    measurement_policy_sha256: template.measurement_policy_sha256,
    compose_hash: template.compose_hash,
    app_id: template.app_id,
    os_image_hash: template.os_image_hash,
    chain_id: template.chain_id,
    max_authorization_lifetime_seconds:
      template.max_authorization_lifetime_seconds,
  };
  const runtimeBinding = {
    ...runtimeWithoutQvlCommitment,
    royalty_qvl_policy_commitment: royaltyRuntimeQvlPolicyCommitment(
      runtimeWithoutQvlCommitment,
      template,
    ),
  };
  return Object.freeze({
    schema: ROYALTY_RUNTIME_BINDING_ADAPTER_SCHEMA,
    status: ROYALTY_RUNTIME_BINDING_ADAPTER_STATUS,
    truth_status: ROYALTY_RUNTIME_BINDING_ADAPTER_TRUTH_STATUS,
    source_binding: sourceBinding,
    source_binding_sha256: sourceBindingSha256,
    reconciliation_receipt: reconciliation,
    runtime_binding: Object.freeze(runtimeBinding),
    runtime_binding_commitment:
      pythonRoyaltyRuntimeBindingCommitment(runtimeBinding),
  });
}

export function royaltyRuntimeBindingAdapterReceiptSha256(value) {
  exactRecord(value, [
    "reconciliation_receipt",
    "runtime_binding",
    "runtime_binding_commitment",
    "schema",
    "source_binding",
    "source_binding_sha256",
    "status",
    "truth_status",
  ], "Royalty runtime-binding adapter receipt");
  const sourceBinding = exactRecord(
    value.source_binding,
    SOURCE_BINDING_FIELDS,
    "Royalty source binding",
  );
  const reconciliation = normalizeRoyaltySettlementReleaseReconciliationReceipt(
    value.reconciliation_receipt,
  );
  const sourceBindingSha256 = digest(
    ROYALTY_SETTLEMENT_RELEASE_BINDING_DOMAIN,
    sourceBinding,
  );
  const runtimeBinding = value.runtime_binding;
  const authority = sourceBinding.royalty_release_authority;
  const template = sourceBinding.royalty_settlement_release_binding_template;
  const expectedRuntimeProjection = {
    distributor_address: authority?.distributor_address,
    distributor_runtime_code_hash: template?.distributor_runtime_code_hash,
    owner_address: authority?.owner,
    authority_nonce: authority?.authority_nonce,
    settlement_verifier_address: authority?.settlement_verifier,
    royalty_qvl_verifier_address: authority?.qvl_verifier,
    execution_policy_anchor_address: authority?.execution_policy_anchor,
    anchor_writer_release_commitment:
      authority?.anchor_writer_release_commitment,
    release_policy_commitment: authority?.release_policy_commitment,
    royalty_qvl_signer_key_id: template?.royalty_qvl_signer_key_id,
    qvl_release_policy_hash: template?.qvl_release_policy_hash,
    main_runtime_cvm_id: template?.main_runtime_cvm_id,
    deployment_intent_sha256: sourceBinding.deployment_intent_sha256,
    release_authority_sha256: sourceBinding.final_release_authority_v4_sha256,
    ceremony_nonce: template?.ceremony_nonce,
    measurement_policy_sha256: template?.measurement_policy_sha256,
    compose_hash: template?.compose_hash,
    app_id: template?.app_id,
    os_image_hash: template?.os_image_hash,
    chain_id: template?.chain_id,
    max_authorization_lifetime_seconds:
      template?.max_authorization_lifetime_seconds,
  };
  const runtimeProjectionMatches = Object.entries(expectedRuntimeProjection)
    .every(([field, expected]) => runtimeBinding?.[field] === expected);
  if (value.schema !== ROYALTY_RUNTIME_BINDING_ADAPTER_SCHEMA
    || value.status !== ROYALTY_RUNTIME_BINDING_ADAPTER_STATUS
    || value.truth_status !== ROYALTY_RUNTIME_BINDING_ADAPTER_TRUTH_STATUS
    || sourceBinding.schema
      !== REQUIRED_ROYALTY_SETTLEMENT_RELEASE_BINDING_SCHEMA
    || value.source_binding_sha256 !== sourceBindingSha256
    || reconciliation.release_sha !== sourceBinding.release_sha
    || reconciliation.deployment_intent_sha256
      !== sourceBinding.deployment_intent_sha256
    || reconciliation.final_release_authority_v4_sha256
      !== sourceBinding.final_release_authority_v4_sha256
    || reconciliation.royalty_release_history_receipt_sha256
      !== sourceBinding.royalty_release_history_receipt_sha256
    || reconciliation.royalty_release_history_sha256
      !== sourceBinding.royalty_release_history_sha256
    || reconciliation.royalty_settlement_release_binding_sha256
      !== sourceBindingSha256
    || !runtimeProjectionMatches
    || runtimeBinding?.royalty_qvl_policy_commitment
      !== royaltyRuntimeQvlPolicyCommitment(runtimeBinding, template)
    || value.runtime_binding_commitment
      !== pythonRoyaltyRuntimeBindingCommitment(runtimeBinding)) {
    fail("Royalty runtime-binding adapter receipt is invalid");
  }
  return digest(ROYALTY_RUNTIME_BINDING_ADAPTER_DOMAIN, value);
}
