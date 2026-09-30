import { createHash } from "node:crypto";

import {
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
  CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES,
  cvmDescriptorDomainRuntimeFactsSha256,
  cvmDescriptorRuntimeAuthoritySha256,
  cvmDescriptorRuntimeFactsSha256,
  normalizeCvmDescriptorRuntimeAuthority,
} from "./cvm-descriptor-runtime-authority-v3-core.mjs";
import {
  PHALA_APP_COMPOSE_WIRE_HASH_SEMANTICS,
} from "./phala-app-compose-wire-core.mjs";
import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_SECRET_PHASES,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-release-verification-authority-v5-core.mjs";
import {
  syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture as
    syntheticHistoricalV4ReleaseFixture,
} from "./current-cvm-authority-v4.fixture.mjs";

export {
  CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
} from "./current-cvm-authority-v4.fixture.mjs";

function currentPhasePolicy(policy) {
  return {
    initial_phase: policy.launch_settings.initial_phase,
    initial_services: [...policy.launch_settings.initial_services],
    initially_enabled_profiles: [
      ...policy.launch_settings.initially_enabled_profiles,
    ],
    initially_disabled_profiles: [
      ...policy.launch_settings.initially_disabled_profiles,
    ],
    encrypted_secret_environment_keys_by_phase: Object.fromEntries(
      CVM_LAUNCH_SECRET_PHASES.map((phase) => [
        phase,
        [...policy.encrypted_secret_environment_keys_by_phase[phase]],
      ]),
    ),
  };
}

function currentPrivacyPolicy(policy) {
  const compose = policy.app_compose_candidate;
  return {
    fresh_cvm_required: policy.launch_settings.fresh_cvm_required,
    fresh_cli_deploy_forbidden:
      policy.launch_settings.fresh_cli_deploy_forbidden,
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

/** Synthetic structure only: these hashes are not measured SDK/CVM evidence. */
export function syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture(
  options = {},
) {
  const raw = structuredClone(syntheticHistoricalV4ReleaseFixture(options));
  const runtime = raw.cvm_descriptor_runtime_authority;
  runtime.schema = CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA;
  runtime.compose_hash_semantics = structuredClone(PHALA_APP_COMPOSE_WIRE_HASH_SEMANTICS);
  runtime.fact_sources = structuredClone(CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES);
  runtime.pre_transform_app_compose_hash_by_domain = {};
  for (const descriptor of runtime.descriptors) {
    // The v4 input is a frozen replay fixture. Project each current domain
    // explicitly so current recipient scope never changes its historical bytes.
    const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[descriptor.domain];
    descriptor.allowed_environment_keys = [
      ...policy.exact_allowed_environment_keys,
    ];
    descriptor.allowed_environment_keys_sha256 =
      policy.exact_allowed_environment_keys_sha256;
    descriptor.descriptor_environment_keys = [...new Set([
      ...policy.exact_allowed_environment_keys.filter(
        (key) => key !== "COMPOSE_PROFILES",
      ),
      ...policy.public_environment_key_classification.descriptor_defaulted_keys,
    ])].sort();
    descriptor.phase_policy = currentPhasePolicy(policy);
    descriptor.privacy_policy = currentPrivacyPolicy(policy);
    descriptor.pre_transform_app_compose_hash = createHash("sha256")
      .update("synthetic-v5-pre-transform-not-runtime:")
      .update(descriptor.domain)
      .update(descriptor.app_compose_hash)
      .digest("hex");
    runtime.pre_transform_app_compose_hash_by_domain[descriptor.domain] =
      descriptor.pre_transform_app_compose_hash;
    descriptor.runtime_facts_sha256 = cvmDescriptorDomainRuntimeFactsSha256(descriptor);
  }
  runtime.descriptor_runtime_facts_sha256 = cvmDescriptorRuntimeFactsSha256(runtime);
  raw.schema = PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA;
  raw.cvm_descriptor_runtime_authority = normalizeCvmDescriptorRuntimeAuthority(runtime);
  raw.cvm_descriptor_runtime_authority_sha256 =
    cvmDescriptorRuntimeAuthoritySha256(raw.cvm_descriptor_runtime_authority);
  return normalizePhalaSevenCvmReleaseVerificationAuthority(raw);
}
