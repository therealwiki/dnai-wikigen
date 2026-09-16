import {
  cvmDescriptorRuntimeAuthoritySha256,
} from "./cvm-descriptor-runtime-authority-core.mjs";
import {
  createUnsafeSyntheticCvmDescriptorRuntimeAuthorityFixture,
} from "./cvm-descriptor-runtime-authority-test-harness.mjs";
import {
  PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
  PHALA_QVL_MEASUREMENT_POLICY_ORDER,
  PHALA_QVL_MEASUREMENT_POLICY_PROFILE,
  PHALA_QVL_MEASUREMENT_POLICY_SCHEMA,
  PHALA_QVL_MEASUREMENT_POLICY_SET_SCHEMA,
  phalaQvlMeasurementPolicySetSha256,
} from "./phala-seven-cvm-measurement-policy.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_STATUS,
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_TRUTH,
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_EXECUTION_ORDER,
  PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";

const bare = (byte) => byte.toString(16).padStart(2, "0").repeat(32);
const sha = (byte) => `sha256:${bare(byte)}`;
const word = (byte) => `0x${bare(byte)}`;
const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;

function policy(domain, index, deploymentIntentSha256) {
  const hex48 = (offset) => ((index * 16) + offset + 1)
    .toString(16).padStart(2, "0").repeat(48);
  return {
    schema: PHALA_QVL_MEASUREMENT_POLICY_SCHEMA,
    domain,
    profile: PHALA_QVL_MEASUREMENT_POLICY_PROFILE[domain],
    deployment_intent_sha256: deploymentIntentSha256,
    reference_id: `${domain.replaceAll("_", "-")}-synthetic-v2`,
    mr_td: hex48(0),
    mr_config_id: hex48(1),
    mr_owner: hex48(2),
    mr_owner_config: hex48(3),
    rt_mr0: hex48(4),
    rt_mr1: hex48(5),
    rt_mr2: hex48(6),
    rt_mr3: hex48(7),
    td_attributes: "02" + "00".repeat(7),
    td_attributes_required_mask: "00".repeat(8),
    td_attributes_forbidden_mask: "01" + "00".repeat(7),
    xfam: "00".repeat(8),
    xfam_required_mask: "00".repeat(8),
    xfam_forbidden_mask: "00".repeat(8),
  };
}

function descriptor(domain, index) {
  return {
    domain,
    descriptor_sha256: sha(20 + index),
    app_id: (40 + index).toString(16).padStart(2, "0").repeat(20),
    cvm_id: `synthetic-cvm-${String(index + 1).padStart(2, "0")}`,
    compose_hash: bare(60 + index),
    os_image_hash: bare(80 + index),
    posture_receipt_sha256: sha(100 + index),
    posture_observed_at: "2033-05-18T03:30:00Z",
    kms_id: "kms-synthetic-01",
    instance_type: index === 0 ? "tdx.large" : "tdx.small",
    disk_size: index === 0 ? 40 : 20,
  };
}

export function syntheticPhalaSevenCvmReleaseDescriptorsFixture({
  mainRuntime = {},
} = {}) {
  if (!mainRuntime || typeof mainRuntime !== "object" || Array.isArray(mainRuntime)
    || JSON.stringify(Object.keys(mainRuntime).sort())
      !== JSON.stringify(Object.keys(mainRuntime).filter((key) => [
        "app_id",
        "compose_hash",
        "cvm_id",
        "descriptor_sha256",
        "os_image_hash",
      ].includes(key)).sort())) {
    throw new TypeError("main runtime descriptor overrides contain an unsupported fixture field");
  }
  return PHALA_SEVEN_CVM_RELEASE_VERIFICATION_EXECUTION_ORDER.map((domain, index) => {
    const base = descriptor(domain, index);
    return domain === "main_runtime_cvm"
      ? { ...base, ...mainRuntime, domain }
      : base;
  });
}

export function syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture({
  releaseSha = "ab".repeat(20),
  deploymentIntentSha256 = sha(180),
  bootstrapAuthorizationReceiptSha256 = sha(181),
  ceremonyNonce = word(182),
  freshContractDeploymentReceiptSha256 = sha(183),
  diligenceRoom = address(700),
  computeCreditVault = address(701),
  computeCreditVaultRuntimeCodeHash = word(184),
  qvlMeasurementPolicies,
  releaseDescriptors,
} = {}) {
  const policies = qvlMeasurementPolicies ?? PHALA_QVL_MEASUREMENT_POLICY_ORDER
    .map((domain, index) => policy(domain, index, deploymentIntentSha256));
  const descriptors = releaseDescriptors
    ?? syntheticPhalaSevenCvmReleaseDescriptorsFixture();
  const policySet = {
    schema: PHALA_QVL_MEASUREMENT_POLICY_SET_SCHEMA,
    chain_id: 84_532,
    deployment_intent_sha256: deploymentIntentSha256,
    activation_evidence_lease_seconds:
      PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
    policies,
  };
  const descriptorRuntimeAuthority =
    createUnsafeSyntheticCvmDescriptorRuntimeAuthorityFixture({
      releaseSha,
      descriptorSetReceiptSha256: sha(185),
      imageManifestSha256: sha(186),
      topologySha256: sha(187),
      descriptorSha256ByDomain: Object.fromEntries(
        descriptors.map((entry) => [entry.domain, entry.descriptor_sha256]),
      ),
      appComposeHashByDomain: Object.fromEntries(
        descriptors.map((entry) => [entry.domain, entry.compose_hash]),
      ),
    });
  return normalizePhalaSevenCvmReleaseVerificationAuthority({
    schema: PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
    status: PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_STATUS,
    truth_status: PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_TRUTH,
    evidence_mode: PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
    chain_id: 84_532,
    release_sha: releaseSha,
    deployment_intent_sha256: deploymentIntentSha256,
    activation_evidence_lease_seconds:
      PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
    bootstrap_authorization_receipt_sha256:
      bootstrapAuthorizationReceiptSha256,
    cvm_descriptor_runtime_authority_sha256:
      cvmDescriptorRuntimeAuthoritySha256(descriptorRuntimeAuthority),
    cvm_descriptor_runtime_authority: descriptorRuntimeAuthority,
    ceremony_nonce: ceremonyNonce,
    qvl_measurement_policy_set_sha256:
      phalaQvlMeasurementPolicySetSha256(policySet),
    qvl_measurement_policies: policies,
    contracts: {
      fresh_contract_deployment_receipt_sha256:
        freshContractDeploymentReceiptSha256,
      diligence_room: diligenceRoom,
      compute_credit_vault: computeCreditVault,
      compute_credit_vault_runtime_code_hash:
        computeCreditVaultRuntimeCodeHash,
    },
    descriptors,
  });
}
