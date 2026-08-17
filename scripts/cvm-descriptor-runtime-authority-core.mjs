import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_LAUNCH_DESCRIPTOR_FILES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_LAUNCH_SECRET_PHASES,
  PHALA_CVM_APP_COMPOSE_NAMES,
} from "./cvm-descriptor-runtime-authority-v1-policy.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
} from "./cvm-release-descriptor-set-constants.mjs";

export const CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA =
  "dnai.cvm-descriptor-runtime-authority.v1";
export const CVM_DESCRIPTOR_RUNTIME_AUTHORITY_DOMAIN =
  "dnai-wikigen/cvm-descriptor-runtime-authority/v1\0";
export const CVM_DESCRIPTOR_RUNTIME_FACTS_DOMAIN =
  "dnai-wikigen/cvm-descriptor-runtime-facts/v1\0";
export const CVM_DESCRIPTOR_DOMAIN_RUNTIME_FACTS_DOMAIN =
  "dnai-wikigen/cvm-descriptor-domain-runtime-facts/v1\0";
export const CVM_DESCRIPTOR_RUNTIME_AUTHORITY_LIFETIME_MS = 120_000;
export const CVM_DESCRIPTOR_MAX_BYTES = 200 * 1024;

const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const ENVIRONMENT_KEY = /^[A-Z][A-Z0-9_]{0,127}$/;
const IMAGE_REFERENCE =
  /^ghcr\.io\/therealwiki\/dnai-wikigen\/[a-z0-9-]+@sha256:(?!0{64}$)[0-9a-f]{64}$/;

export const CVM_DESCRIPTOR_STABLE_READ_POLICY = Object.freeze({
  exact_canonical_file_count: 7,
  maximum_descriptor_bytes: CVM_DESCRIPTOR_MAX_BYTES,
  symbolic_links_allowed: false,
  hard_links_allowed: false,
  owner: "effective_process_uid",
  group_or_world_writable_allowed: false,
  file_identity_and_metadata_rechecked_after_read: true,
  release_directory_identity_rechecked_after_all_reads: true,
});

export const CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES = Object.freeze({
  descriptor_bytes:
    "fresh_stable_owned_nonwritable_raw_bytes_revalidated_by_canonical_descriptor_set_validator",
  app_compose_wrapper:
    "reviewed_CVM_LAUNCH_DESCRIPTOR_POLICY_app_compose_candidate_plus_exact_allowed_environment_keys",
  phase_and_privacy_policy:
    "reviewed_CVM_LAUNCH_DESCRIPTOR_POLICY_launch_settings_and_environment_classification",
  descriptor_set_binding:
    "same_invocation_validateCanonicalGeneratedCvmDescriptorSet_receipt",
  caller_supplied_hash_or_fact_association: false,
});

export const CVM_DESCRIPTOR_EXTERNAL_RUNTIME_AUTHORITY_REQUIREMENTS = Object.freeze({
  kms_id:
    "required_from_independently_branded_fresh_production_target_and_prepare_authority",
  instance_type_and_disk_size:
    "required_from_independently_branded_fresh_production_target_prepare_and_posture_authority",
  app_id_and_cvm_id:
    "required_from_independently_branded_completed_provision_and_fresh_posture_authority",
  os_image_and_runtime_posture:
    "required_from_independently_branded_fresh_target_prepare_and_getCvmInfo_posture_authority",
  claimed_by_this_authority: false,
});

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function exactDigest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactTimestamp(value, label) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))
    || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function same(value, expected) {
  return JSON.stringify(value) === JSON.stringify(expected);
}

function sortedUniqueStrings(value, label, pattern = undefined) {
  if (!Array.isArray(value)
    || value.some((item) => typeof item !== "string"
      || (pattern && !pattern.test(item)))
    || value.length !== new Set(value).size
    || !same(value, [...value].sort())) {
    throw new Error(`${label} must be a sorted unique canonical string set`);
  }
  return [...value];
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

function domainFactsWithoutDigest(value) {
  const copy = structuredClone(value);
  delete copy.runtime_facts_sha256;
  return copy;
}

export function cvmDescriptorDomainRuntimeFactsSha256(value) {
  return domainDigest(
    CVM_DESCRIPTOR_DOMAIN_RUNTIME_FACTS_DOMAIN,
    domainFactsWithoutDigest(value),
  );
}

export function normalizeCvmDescriptorDomainRuntimeFacts(value, domain) {
  assertCanonicalPlainDataGraph(value, {
    label: `${domain} CVM descriptor runtime facts`,
  });
  if (!CVM_LAUNCH_DOMAINS.includes(domain)) {
    throw new Error("descriptor runtime facts domain is not canonical");
  }
  const parsed = exactRecord(value, [
    "domain",
    "descriptor_file",
    "descriptor_sha256",
    "descriptor_byte_length",
    "app_compose_name",
    "app_compose_hash",
    "service_images",
    "image_references",
    "descriptor_environment_keys",
    "allowed_environment_keys",
    "allowed_environment_keys_sha256",
    "phase_policy",
    "privacy_policy",
    "runtime_facts_sha256",
  ], `${domain} descriptor runtime facts`);
  if (parsed.domain !== domain
    || parsed.descriptor_file !== CVM_LAUNCH_DESCRIPTOR_FILES[domain]
    || parsed.app_compose_name !== PHALA_CVM_APP_COMPOSE_NAMES[domain]
    || !Number.isSafeInteger(parsed.descriptor_byte_length)
    || parsed.descriptor_byte_length < 2
    || parsed.descriptor_byte_length > CVM_DESCRIPTOR_MAX_BYTES
    || typeof parsed.app_compose_hash !== "string"
    || !BARE_SHA256.test(parsed.app_compose_hash)) {
    throw new Error(`${domain} descriptor runtime identity is invalid`);
  }
  const descriptorSha256 = exactDigest(
    parsed.descriptor_sha256,
    `${domain} raw descriptor bytes`,
  );
  const expectedServices = CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain];
  if (!Array.isArray(parsed.service_images)
    || parsed.service_images.length !== expectedServices.length) {
    throw new Error(`${domain} service-image facts are incomplete`);
  }
  const serviceImages = parsed.service_images.map((entry, index) => {
    const item = exactRecord(entry, ["service", "image"], `${domain} service image ${index}`);
    if (item.service !== expectedServices[index]
      || typeof item.image !== "string" || !IMAGE_REFERENCE.test(item.image)) {
      throw new Error(`${domain} service-image facts are not canonical`);
    }
    return { service: item.service, image: item.image };
  });
  const imageReferences = sortedUniqueStrings(
    parsed.image_references,
    `${domain} image references`,
    IMAGE_REFERENCE,
  );
  const derivedImages = [...new Set(serviceImages.map(({ image }) => image))].sort();
  if (!same(imageReferences, derivedImages)) {
    throw new Error(`${domain} image references do not derive from its service map`);
  }
  const descriptorEnvironmentKeys = sortedUniqueStrings(
    parsed.descriptor_environment_keys,
    `${domain} descriptor environment keys`,
    ENVIRONMENT_KEY,
  );
  const allowedEnvironmentKeys = sortedUniqueStrings(
    parsed.allowed_environment_keys,
    `${domain} allowed environment keys`,
    ENVIRONMENT_KEY,
  );
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  if (!same(descriptorEnvironmentKeys, expectedDescriptorEnvironmentKeys(domain))
    || !same(allowedEnvironmentKeys, policy.exact_allowed_environment_keys)
    || parsed.allowed_environment_keys_sha256
      !== policy.exact_allowed_environment_keys_sha256
    || !same(parsed.phase_policy, expectedPhasePolicy(domain))
    || !same(parsed.privacy_policy, expectedPrivacyPolicy(domain))) {
    throw new Error(`${domain} descriptor environment, phase, or privacy policy drifted`);
  }
  const normalized = {
    domain,
    descriptor_file: CVM_LAUNCH_DESCRIPTOR_FILES[domain],
    descriptor_sha256: descriptorSha256,
    descriptor_byte_length: parsed.descriptor_byte_length,
    app_compose_name: PHALA_CVM_APP_COMPOSE_NAMES[domain],
    app_compose_hash: parsed.app_compose_hash,
    service_images: serviceImages,
    image_references: imageReferences,
    descriptor_environment_keys: descriptorEnvironmentKeys,
    allowed_environment_keys: allowedEnvironmentKeys,
    allowed_environment_keys_sha256: policy.exact_allowed_environment_keys_sha256,
    phase_policy: expectedPhasePolicy(domain),
    privacy_policy: expectedPrivacyPolicy(domain),
    runtime_facts_sha256: exactDigest(
      parsed.runtime_facts_sha256,
      `${domain} runtime facts`,
    ),
  };
  if (normalized.runtime_facts_sha256
    !== cvmDescriptorDomainRuntimeFactsSha256(normalized)) {
    throw new Error(`${domain} runtime facts are not bound to their exact values`);
  }
  return normalized;
}

export function createCvmDescriptorDomainRuntimeFacts({
  domain,
  descriptorSha256,
  descriptorByteLength,
  appComposeHash,
  serviceImages,
  descriptorEnvironmentKeys,
} = {}) {
  if (!CVM_LAUNCH_DOMAINS.includes(domain)) {
    throw new Error("descriptor runtime facts domain is not canonical");
  }
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const facts = {
    domain,
    descriptor_file: CVM_LAUNCH_DESCRIPTOR_FILES[domain],
    descriptor_sha256: descriptorSha256,
    descriptor_byte_length: descriptorByteLength,
    app_compose_name: PHALA_CVM_APP_COMPOSE_NAMES[domain],
    app_compose_hash: appComposeHash,
    service_images: serviceImages,
    image_references: [...new Set(serviceImages.map(({ image }) => image))].sort(),
    descriptor_environment_keys: [...descriptorEnvironmentKeys].sort(),
    allowed_environment_keys: [...policy.exact_allowed_environment_keys],
    allowed_environment_keys_sha256: policy.exact_allowed_environment_keys_sha256,
    phase_policy: expectedPhasePolicy(domain),
    privacy_policy: expectedPrivacyPolicy(domain),
    runtime_facts_sha256: null,
  };
  facts.runtime_facts_sha256 = cvmDescriptorDomainRuntimeFactsSha256(facts);
  return normalizeCvmDescriptorDomainRuntimeFacts(facts, domain);
}

function runtimeFactsDigestInput(value) {
  return {
    release_sha: value.release_sha,
    descriptor_set_receipt_sha256: value.descriptor_set_receipt_sha256,
    descriptor_sha256_by_domain: value.descriptor_sha256_by_domain,
    app_compose_hash_by_domain: value.app_compose_hash_by_domain,
    descriptors: value.descriptors,
  };
}

export function cvmDescriptorRuntimeFactsSha256(value) {
  return domainDigest(
    CVM_DESCRIPTOR_RUNTIME_FACTS_DOMAIN,
    runtimeFactsDigestInput(value),
  );
}

export function normalizeCvmDescriptorRuntimeAuthority(value) {
  assertCanonicalPlainDataGraph(value, { label: "CVM descriptor runtime authority" });
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    "release_sha",
    "source_ref",
    "descriptor_set_receipt_schema",
    "descriptor_set_receipt_sha256",
    "image_manifest_sha256",
    "topology_sha256",
    "descriptor_sha256_by_domain",
    "app_compose_hash_by_domain",
    "descriptor_runtime_facts_sha256",
    "stable_read_policy",
    "fact_sources",
    "external_runtime_authority_requirements",
    "descriptors",
    "read_started_at",
    "read_completed_at",
    "expires_at",
    "invariants",
  ], "CVM descriptor runtime authority");
  if (parsed.schema !== CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA
    || parsed.status !== "fresh_stable_descriptor_runtime_authority"
    || parsed.truth_status
      !== "fresh_local_descriptor_bytes_and_reviewed_launch_policy_not_phala_deployment_runtime_or_tdx_evidence"
    || typeof parsed.release_sha !== "string" || !SHA40.test(parsed.release_sha)
    || typeof parsed.source_ref !== "string"
    || !/^refs\/(?:heads\/main|tags\/v[0-9][0-9A-Za-z._-]*)$/.test(parsed.source_ref)
    || parsed.descriptor_set_receipt_schema !== CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA
    || !same(parsed.stable_read_policy, CVM_DESCRIPTOR_STABLE_READ_POLICY)
    || !same(parsed.fact_sources, CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES)
    || !same(
      parsed.external_runtime_authority_requirements,
      CVM_DESCRIPTOR_EXTERNAL_RUNTIME_AUTHORITY_REQUIREMENTS,
    )) {
    throw new Error("CVM descriptor runtime authority identity or evidence boundary is invalid");
  }
  const descriptors = Array.isArray(parsed.descriptors)
    ? parsed.descriptors.map((entry, index) => normalizeCvmDescriptorDomainRuntimeFacts(
      entry,
      CVM_LAUNCH_DOMAINS[index],
    ))
    : [];
  if (descriptors.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("CVM descriptor runtime authority must contain exact seven-domain facts");
  }
  const descriptorMap = exactRecord(
    parsed.descriptor_sha256_by_domain,
    CVM_LAUNCH_DOMAINS,
    "descriptor SHA-256 map",
  );
  const composeMap = exactRecord(
    parsed.app_compose_hash_by_domain,
    CVM_LAUNCH_DOMAINS,
    "AppCompose hash map",
  );
  const descriptorSha256ByDomain = {};
  const appComposeHashByDomain = {};
  for (const [index, domain] of CVM_LAUNCH_DOMAINS.entries()) {
    descriptorSha256ByDomain[domain] = exactDigest(
      descriptorMap[domain],
      `${domain} descriptor map digest`,
    );
    if (descriptorSha256ByDomain[domain] !== descriptors[index].descriptor_sha256
      || typeof composeMap[domain] !== "string"
      || !BARE_SHA256.test(composeMap[domain])
      || composeMap[domain] !== descriptors[index].app_compose_hash) {
      throw new Error(`${domain} aggregate maps do not equal exact runtime facts`);
    }
    appComposeHashByDomain[domain] = composeMap[domain];
  }
  if (new Set(Object.values(descriptorSha256ByDomain)).size !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("seven runtime descriptor hashes must be pairwise distinct");
  }
  const readStartedAt = exactTimestamp(parsed.read_started_at, "read_started_at");
  const readCompletedAt = exactTimestamp(parsed.read_completed_at, "read_completed_at");
  const expiresAt = exactTimestamp(parsed.expires_at, "expires_at");
  if (Date.parse(readCompletedAt) < Date.parse(readStartedAt)
    || Date.parse(expiresAt) - Date.parse(readCompletedAt)
      !== CVM_DESCRIPTOR_RUNTIME_AUTHORITY_LIFETIME_MS) {
    throw new Error("descriptor runtime authority read or expiry interval is invalid");
  }
  const invariants = exactRecord(parsed.invariants, [
    "exact_seven_canonical_files",
    "raw_descriptor_bytes_freshly_stable_read",
    "descriptor_set_receipt_revalidated",
    "caller_supplied_descriptor_hashes_or_facts",
    "symlinks_or_hardlinks",
    "group_or_world_writable_files",
    "runtime_resource_or_identity_claimed",
    "deployment_or_tdx_claimed",
  ], "descriptor runtime authority invariants");
  const expectedInvariants = {
    exact_seven_canonical_files: true,
    raw_descriptor_bytes_freshly_stable_read: true,
    descriptor_set_receipt_revalidated: true,
    caller_supplied_descriptor_hashes_or_facts: false,
    symlinks_or_hardlinks: false,
    group_or_world_writable_files: false,
    runtime_resource_or_identity_claimed: false,
    deployment_or_tdx_claimed: false,
  };
  if (!same(invariants, expectedInvariants)) {
    throw new Error("descriptor runtime authority invariants are invalid");
  }
  const normalized = {
    schema: CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
    status: "fresh_stable_descriptor_runtime_authority",
    truth_status:
      "fresh_local_descriptor_bytes_and_reviewed_launch_policy_not_phala_deployment_runtime_or_tdx_evidence",
    release_sha: parsed.release_sha,
    source_ref: parsed.source_ref,
    descriptor_set_receipt_schema: CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
    descriptor_set_receipt_sha256: exactDigest(
      parsed.descriptor_set_receipt_sha256,
      "descriptor-set receipt",
    ),
    image_manifest_sha256: exactDigest(
      parsed.image_manifest_sha256,
      "image release manifest",
    ),
    topology_sha256: exactDigest(parsed.topology_sha256, "CVM topology"),
    descriptor_sha256_by_domain: descriptorSha256ByDomain,
    app_compose_hash_by_domain: appComposeHashByDomain,
    descriptor_runtime_facts_sha256: exactDigest(
      parsed.descriptor_runtime_facts_sha256,
      "descriptor runtime facts",
    ),
    stable_read_policy: structuredClone(CVM_DESCRIPTOR_STABLE_READ_POLICY),
    fact_sources: structuredClone(CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES),
    external_runtime_authority_requirements: structuredClone(
      CVM_DESCRIPTOR_EXTERNAL_RUNTIME_AUTHORITY_REQUIREMENTS,
    ),
    descriptors,
    read_started_at: readStartedAt,
    read_completed_at: readCompletedAt,
    expires_at: expiresAt,
    invariants: expectedInvariants,
  };
  if (normalized.descriptor_runtime_facts_sha256
    !== cvmDescriptorRuntimeFactsSha256(normalized)) {
    throw new Error("aggregate descriptor runtime facts digest is invalid");
  }
  return deepFreezeCanonicalPlainDataGraph(normalized, {
    label: "normalized CVM descriptor runtime authority",
  });
}

export function canonicalCvmDescriptorRuntimeAuthorityText(value) {
  return canonicalText(normalizeCvmDescriptorRuntimeAuthority(value));
}

export function cvmDescriptorRuntimeAuthoritySha256(value) {
  return domainDigest(
    CVM_DESCRIPTOR_RUNTIME_AUTHORITY_DOMAIN,
    normalizeCvmDescriptorRuntimeAuthority(value),
  );
}
