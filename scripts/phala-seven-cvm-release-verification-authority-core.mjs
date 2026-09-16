import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_LAUNCH_DOMAINS,
} from "./cvm-launch-intent-core.mjs";
import {
  cvmDescriptorRuntimeAuthoritySha256,
  normalizeCvmDescriptorRuntimeAuthority,
} from "./cvm-descriptor-runtime-authority-core.mjs";
import {
  PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
  PHALA_QVL_MEASUREMENT_POLICY_ORDER,
  PHALA_QVL_MEASUREMENT_POLICY_SET_SCHEMA,
  normalizePhalaQvlMeasurementPolicy,
  phalaQvlMeasurementPolicySetSha256,
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";

export const PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA =
  "dnai.phala-seven-cvm-release-verification-authority.v3";
export const PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_DOMAIN =
  "dnai-wikigen/phala-seven-cvm-release-verification-authority/v3\0";
export const PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_STATUS =
  "signed_launch_observed_seven_cvm_and_activation_evidence_lease_authority_bound";
export const PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_TRUTH =
  "signed_a_measurement_policies_activation_evidence_lease_contracts_descriptor_runtime_and_seven_get_cvm_info_resource_posture_observations_bound";
export const PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE =
  "production_pinned_local_dcap_frozen_offline_dependencies_authenticated_pccs_collateral_and_qvl_signatures";
export const PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE =
  "synthetic_node_test_fixture_never_live_release_authority";
export const PHALA_SEVEN_CVM_RELEASE_VERIFICATION_EXECUTION_ORDER =
  Object.freeze([...CVM_LAUNCH_DOMAINS]);

const BASE_SEPOLIA_CHAIN_ID = 84_532;
const MAX_AUTHORITY_BYTES = 128 * 1024;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const INSTANCE_TYPE = /^[a-z][a-z0-9.-]{1,63}$/;
const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)) {
    throw new TypeError(`${label} must contain exactly the frozen fields`);
  }
  const prototype = Object.getPrototypeOf(value);
  const ownKeys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
    || ownKeys.some((key) => typeof key !== "string")
    || JSON.stringify(ownKeys.sort()) !== JSON.stringify([...fields].sort())
    || Object.values(descriptors).some((descriptor) =>
      !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true)) {
    throw new TypeError(`${label} must contain exactly the frozen fields`);
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

function digest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be one nonzero canonical SHA-256 digest`);
  }
  return value;
}

function fixed(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new TypeError(`${label} is not canonical fixed-width lowercase data`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new TypeError(`${label} must be one canonical identifier`);
  }
  return value;
}

function timestamp(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)) {
    throw new TypeError(`${label} must be one canonical UTC second`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)
    || new Date(parsed).toISOString().replace(".000Z", "Z") !== value) {
    throw new TypeError(`${label} must round-trip as one canonical UTC second`);
  }
  return value;
}

export function normalizePhalaSevenCvmReleaseVerificationDescriptor(
  value,
  expectedDomain,
) {
  if (!PHALA_SEVEN_CVM_RELEASE_VERIFICATION_EXECUTION_ORDER.includes(expectedDomain)) {
    throw new TypeError("release verification descriptor domain is unknown");
  }
  const parsed = exactRecord(value, [
    "app_id", "compose_hash", "cvm_id", "descriptor_sha256", "disk_size",
    "domain", "instance_type", "kms_id", "os_image_hash",
    "posture_observed_at", "posture_receipt_sha256",
  ], `${expectedDomain} release verification descriptor`);
  if (parsed.domain !== expectedDomain) {
    throw new TypeError(
      "release verification descriptors are omitted, reordered, or cross-domain",
    );
  }
  if (!Number.isSafeInteger(parsed.disk_size)
    || parsed.disk_size < 20 || parsed.disk_size > 16_384) {
    throw new TypeError(`${expectedDomain} release verification disk size is invalid`);
  }
  return Object.freeze({
    domain: expectedDomain,
    descriptor_sha256: digest(
      parsed.descriptor_sha256,
      `${expectedDomain} descriptor digest`,
    ),
    app_id: fixed(parsed.app_id, APP_ID, `${expectedDomain} app ID`),
    cvm_id: identifier(parsed.cvm_id, `${expectedDomain} CVM ID`),
    compose_hash: fixed(
      parsed.compose_hash,
      BARE_SHA256,
      `${expectedDomain} compose hash`,
    ),
    os_image_hash: fixed(
      parsed.os_image_hash,
      BARE_SHA256,
      `${expectedDomain} OS image hash`,
    ),
    posture_receipt_sha256: digest(
      parsed.posture_receipt_sha256,
      `${expectedDomain} posture receipt digest`,
    ),
    posture_observed_at: timestamp(
      parsed.posture_observed_at,
      `${expectedDomain} posture observed_at`,
    ),
    kms_id: identifier(parsed.kms_id, `${expectedDomain} KMS ID`),
    instance_type: fixed(
      parsed.instance_type,
      INSTANCE_TYPE,
      `${expectedDomain} instance type`,
    ),
    disk_size: parsed.disk_size,
  });
}

export function normalizePhalaSevenCvmReleaseVerificationAuthority(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "seven-CVM release verification authority input",
  });
  const parsed = exactRecord(value, [
    "activation_evidence_lease_seconds", "bootstrap_authorization_receipt_sha256",
    "ceremony_nonce", "chain_id",
    "contracts", "cvm_descriptor_runtime_authority",
    "cvm_descriptor_runtime_authority_sha256",
    "deployment_intent_sha256", "descriptors", "evidence_mode",
    "qvl_measurement_policies", "qvl_measurement_policy_set_sha256", "release_sha",
    "schema", "status", "truth_status",
  ], "seven-CVM release verification authority");
  if (parsed.schema !== PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA
    || parsed.status !== PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_STATUS
    || parsed.truth_status !== PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_TRUTH
    || parsed.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || parsed.activation_evidence_lease_seconds
      !== PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS
    || ![
      PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
      PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
    ].includes(parsed.evidence_mode)
    || typeof parsed.release_sha !== "string"
    || !RELEASE_SHA.test(parsed.release_sha)
    || !Array.isArray(parsed.descriptors)
    || parsed.descriptors.length
      !== PHALA_SEVEN_CVM_RELEASE_VERIFICATION_EXECUTION_ORDER.length
    || !Array.isArray(parsed.qvl_measurement_policies)
    || parsed.qvl_measurement_policies.length
      !== PHALA_QVL_MEASUREMENT_POLICY_ORDER.length) {
    throw new TypeError("seven-CVM release verification authority is invalid");
  }

  const deploymentIntentSha256 = digest(
    parsed.deployment_intent_sha256,
    "release verification deployment intent",
  );
  const descriptors = parsed.descriptors.map((entry, index) => (
    normalizePhalaSevenCvmReleaseVerificationDescriptor(
      entry,
      PHALA_SEVEN_CVM_RELEASE_VERIFICATION_EXECUTION_ORDER[index],
    )
  ));
  for (const [field, label] of [
    ["app_id", "app IDs"],
    ["cvm_id", "CVM IDs"],
    ["compose_hash", "compose hashes"],
    ["posture_receipt_sha256", "posture receipt digests"],
  ]) {
    if (new Set(descriptors.map((entry) => entry[field])).size !== descriptors.length) {
      throw new TypeError(`release verification descriptor ${label} must be pairwise distinct`);
    }
  }

  const descriptorRuntimeAuthority = normalizeCvmDescriptorRuntimeAuthority(
    parsed.cvm_descriptor_runtime_authority,
  );
  const descriptorRuntimeAuthoritySha256 = cvmDescriptorRuntimeAuthoritySha256(
    descriptorRuntimeAuthority,
  );
  if (descriptorRuntimeAuthority.release_sha !== parsed.release_sha
    || descriptorRuntimeAuthoritySha256
      !== digest(
        parsed.cvm_descriptor_runtime_authority_sha256,
        "release verification CVM descriptor runtime authority",
      )) {
    throw new TypeError(
      "release verification descriptor runtime authority object or digest drifted",
    );
  }
  for (const descriptor of descriptors) {
    if (descriptorRuntimeAuthority.descriptor_sha256_by_domain[descriptor.domain]
        !== descriptor.descriptor_sha256
      || descriptorRuntimeAuthority.app_compose_hash_by_domain[descriptor.domain]
        !== descriptor.compose_hash) {
      throw new TypeError(
        `${descriptor.domain} release verification descriptor differs from its runtime authority`,
      );
    }
  }

  const policies = parsed.qvl_measurement_policies.map(
    normalizePhalaQvlMeasurementPolicy,
  );
  if (JSON.stringify(policies.map(({ domain }) => domain))
      !== JSON.stringify(PHALA_QVL_MEASUREMENT_POLICY_ORDER)
    || policies.some((policy) => (
      policy.deployment_intent_sha256 !== deploymentIntentSha256
    ))
    || new Set(policies.map(phalaQvlMeasurementPolicySha256)).size
      !== policies.length) {
    throw new TypeError(
      "release verification measurement policies are reordered, duplicated, or cross-release",
    );
  }
  const policySet = {
    schema: PHALA_QVL_MEASUREMENT_POLICY_SET_SCHEMA,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    deployment_intent_sha256: deploymentIntentSha256,
    activation_evidence_lease_seconds:
      PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
    policies,
  };
  const canonicalPolicySetSha256 = phalaQvlMeasurementPolicySetSha256(policySet);
  const carriedPolicySetSha256 = digest(
    parsed.qvl_measurement_policy_set_sha256,
    "release verification measurement policy set",
  );
  if (carriedPolicySetSha256 !== canonicalPolicySetSha256) {
    throw new TypeError(
      "release verification measurement policy set digest differs from canonical policy bytes",
    );
  }

  const contracts = exactRecord(parsed.contracts, [
    "compute_credit_vault", "compute_credit_vault_runtime_code_hash",
    "diligence_room", "fresh_contract_deployment_receipt_sha256",
  ], "release verification contract authority");
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
    status: PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_STATUS,
    truth_status: PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_TRUTH,
    evidence_mode: parsed.evidence_mode,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    release_sha: parsed.release_sha,
    deployment_intent_sha256: deploymentIntentSha256,
    activation_evidence_lease_seconds:
      PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
    bootstrap_authorization_receipt_sha256: digest(
      parsed.bootstrap_authorization_receipt_sha256,
      "release verification signed A receipt",
    ),
    cvm_descriptor_runtime_authority_sha256: descriptorRuntimeAuthoritySha256,
    cvm_descriptor_runtime_authority: descriptorRuntimeAuthority,
    ceremony_nonce: fixed(
      parsed.ceremony_nonce,
      BYTES32,
      "release verification ceremony nonce",
    ),
    qvl_measurement_policy_set_sha256: carriedPolicySetSha256,
    qvl_measurement_policies: policies,
    contracts: {
      fresh_contract_deployment_receipt_sha256: digest(
        contracts.fresh_contract_deployment_receipt_sha256,
        "release verification fresh contract deployment receipt",
      ),
      diligence_room: fixed(
        contracts.diligence_room,
        ADDRESS,
        "release verification DiligenceRoom address",
      ),
      compute_credit_vault: fixed(
        contracts.compute_credit_vault,
        ADDRESS,
        "release verification ComputeCreditVault address",
      ),
      compute_credit_vault_runtime_code_hash: fixed(
        contracts.compute_credit_vault_runtime_code_hash,
        BYTES32,
        "release verification ComputeCreditVault runtime code hash",
      ),
    },
    descriptors,
  }, { label: "seven-CVM release verification authority" });
}

export function canonicalPhalaSevenCvmReleaseVerificationAuthorityText(value) {
  const text = `${JSON.stringify(
    sorted(normalizePhalaSevenCvmReleaseVerificationAuthority(value)),
    null,
    2,
  )}\n`;
  if (Buffer.byteLength(text, "utf8") > MAX_AUTHORITY_BYTES) {
    throw new TypeError("seven-CVM release verification authority exceeds its byte bound");
  }
  return text;
}

export function phalaSevenCvmReleaseVerificationAuthoritySha256(value) {
  return `sha256:${createHash("sha256")
    .update(PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_DOMAIN, "utf8")
    .update(canonicalPhalaSevenCvmReleaseVerificationAuthorityText(value), "utf8")
    .digest("hex")}`;
}
