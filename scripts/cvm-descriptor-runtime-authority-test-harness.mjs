import { createHash } from "node:crypto";

import {
  CVM_LAUNCH_DESCRIPTOR_FILES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_LAUNCH_SECRET_PHASES,
  PHALA_CVM_APP_COMPOSE_NAMES,
} from "./cvm-launch-intent-core.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
} from "./cvm-release-descriptor-set-constants.mjs";
import {
  CVM_DESCRIPTOR_DOMAIN_RUNTIME_FACTS_DOMAIN,
  CVM_DESCRIPTOR_EXTERNAL_RUNTIME_AUTHORITY_REQUIREMENTS,
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_LIFETIME_MS,
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
  CVM_DESCRIPTOR_RUNTIME_FACTS_DOMAIN,
  CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES,
  CVM_DESCRIPTOR_STABLE_READ_POLICY,
  normalizeCvmDescriptorRuntimeAuthority,
} from "./cvm-descriptor-runtime-authority-core.mjs";

export const UNSAFE_SYNTHETIC_CVM_DESCRIPTOR_RUNTIME_AUTHORITY_FIXTURE_TRUTH =
  "explicit_unbranded_test_fixture_never_fresh_runtime_authority";

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new TypeError(`${label} must contain exactly the fixture fields`);
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

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(`${JSON.stringify(sorted(value), null, 2)}\n`, "utf8")
    .digest("hex")}`;
}

function expectedDescriptorEnvironmentKeys(domain) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  return [...new Set([
    ...policy.exact_allowed_environment_keys.filter((key) => key !== "COMPOSE_PROFILES"),
    ...policy.public_environment_key_classification.descriptor_defaulted_keys,
  ])].sort();
}

function expectedPhasePolicy(domain) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  return {
    initial_phase: policy.launch_settings.initial_phase,
    initial_services: [...policy.launch_settings.initial_services],
    initially_enabled_profiles: [...policy.launch_settings.initially_enabled_profiles],
    initially_disabled_profiles: [...policy.launch_settings.initially_disabled_profiles],
    encrypted_secret_environment_keys_by_phase: Object.fromEntries(
      CVM_LAUNCH_SECRET_PHASES.map((phase) => [
        phase,
        [...policy.encrypted_secret_environment_keys_by_phase[phase]],
      ]),
    ),
  };
}

function expectedPrivacyPolicy(domain) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const compose = policy.app_compose_candidate;
  return {
    fresh_cvm_required: policy.launch_settings.fresh_cvm_required,
    fresh_cli_deploy_forbidden: policy.launch_settings.fresh_cli_deploy_forbidden,
    no_dev_os: policy.launch_settings.deployment_flags.no_dev_os,
    listed: policy.launch_settings.post_create_assertions.listed,
    public_logs: compose.public_logs,
    public_sysinfo: compose.public_sysinfo,
    public_tcbinfo: compose.public_tcbinfo,
    kms_enabled: compose.kms_enabled,
    gateway_enabled: compose.gateway_enabled,
    secure_time: compose.secure_time,
    tproxy_enabled: compose.tproxy_enabled,
    storage_fs: compose.storage_fs,
  };
}

function withoutRuntimeFactsDigest(value) {
  const copy = structuredClone(value);
  delete copy.runtime_facts_sha256;
  return copy;
}

function aggregateFactsInput(value) {
  return {
    release_sha: value.release_sha,
    descriptor_set_receipt_sha256: value.descriptor_set_receipt_sha256,
    descriptor_sha256_by_domain: value.descriptor_sha256_by_domain,
    app_compose_hash_by_domain: value.app_compose_hash_by_domain,
    descriptors: value.descriptors,
  };
}

/**
 * Builds normalized synthetic bytes for fixture consumers only.
 *
 * The returned value is intentionally not placed in the production facade's
 * private WeakMap, so assertFreshCvmDescriptorRuntimeAuthority always rejects
 * it even when a caller spoofs node:test process metadata.
 */
export function createUnsafeSyntheticCvmDescriptorRuntimeAuthorityFixture({
  releaseSha,
  descriptorSetReceiptSha256,
  imageManifestSha256,
  topologySha256,
  descriptorSha256ByDomain,
  appComposeHashByDomain,
  readStartedAt = "2033-05-18T03:31:00.000Z",
  readCompletedAt = "2033-05-18T03:31:01.000Z",
} = {}) {
  const descriptorMap = exactRecord(
    descriptorSha256ByDomain,
    CVM_LAUNCH_DOMAINS,
    "synthetic descriptor SHA-256 map",
  );
  const composeMap = exactRecord(
    appComposeHashByDomain,
    CVM_LAUNCH_DOMAINS,
    "synthetic AppCompose hash map",
  );
  const descriptors = CVM_LAUNCH_DOMAINS.map((domain, domainIndex) => {
    const serviceImages = CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain]
      .map((service, serviceIndex) => ({
        service,
        image: `ghcr.io/therealwiki/dnai-wikigen/${service}@sha256:${createHash("sha256")
          .update(`synthetic:${domainIndex}:${serviceIndex}`, "utf8")
          .digest("hex")}`,
      }));
    const candidate = {
      domain,
      descriptor_file: CVM_LAUNCH_DESCRIPTOR_FILES[domain],
      descriptor_sha256: descriptorMap[domain],
      descriptor_byte_length: 1_024 + domainIndex,
      app_compose_name: PHALA_CVM_APP_COMPOSE_NAMES[domain],
      app_compose_hash: composeMap[domain],
      service_images: serviceImages,
      image_references: [...new Set(serviceImages.map(({ image }) => image))].sort(),
      descriptor_environment_keys: expectedDescriptorEnvironmentKeys(domain),
      allowed_environment_keys: [
        ...CVM_LAUNCH_DESCRIPTOR_POLICY[domain].exact_allowed_environment_keys,
      ],
      allowed_environment_keys_sha256:
        CVM_LAUNCH_DESCRIPTOR_POLICY[domain].exact_allowed_environment_keys_sha256,
      phase_policy: expectedPhasePolicy(domain),
      privacy_policy: expectedPrivacyPolicy(domain),
      runtime_facts_sha256: null,
    };
    candidate.runtime_facts_sha256 = domainDigest(
      CVM_DESCRIPTOR_DOMAIN_RUNTIME_FACTS_DOMAIN,
      withoutRuntimeFactsDigest(candidate),
    );
    return candidate;
  });
  const completedAt = new Date(readCompletedAt).toISOString();
  const candidate = {
    schema: CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
    status: "fresh_stable_descriptor_runtime_authority",
    truth_status:
      "fresh_local_descriptor_bytes_and_reviewed_launch_policy_not_phala_deployment_runtime_or_tdx_evidence",
    release_sha: releaseSha,
    source_ref: "refs/heads/main",
    descriptor_set_receipt_schema: CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
    descriptor_set_receipt_sha256: descriptorSetReceiptSha256,
    image_manifest_sha256: imageManifestSha256,
    topology_sha256: topologySha256,
    descriptor_sha256_by_domain: { ...descriptorMap },
    app_compose_hash_by_domain: { ...composeMap },
    descriptor_runtime_facts_sha256: null,
    stable_read_policy: structuredClone(CVM_DESCRIPTOR_STABLE_READ_POLICY),
    fact_sources: structuredClone(CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES),
    external_runtime_authority_requirements: structuredClone(
      CVM_DESCRIPTOR_EXTERNAL_RUNTIME_AUTHORITY_REQUIREMENTS,
    ),
    descriptors,
    read_started_at: new Date(readStartedAt).toISOString(),
    read_completed_at: completedAt,
    expires_at: new Date(
      Date.parse(completedAt) + CVM_DESCRIPTOR_RUNTIME_AUTHORITY_LIFETIME_MS,
    ).toISOString(),
    invariants: {
      exact_seven_canonical_files: true,
      raw_descriptor_bytes_freshly_stable_read: true,
      descriptor_set_receipt_revalidated: true,
      caller_supplied_descriptor_hashes_or_facts: false,
      symlinks_or_hardlinks: false,
      group_or_world_writable_files: false,
      runtime_resource_or_identity_claimed: false,
      deployment_or_tdx_claimed: false,
    },
  };
  candidate.descriptor_runtime_facts_sha256 = domainDigest(
    CVM_DESCRIPTOR_RUNTIME_FACTS_DOMAIN,
    aggregateFactsInput(candidate),
  );
  return normalizeCvmDescriptorRuntimeAuthority(candidate);
}
