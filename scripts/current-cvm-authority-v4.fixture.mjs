import {
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
  cvmDescriptorDomainRuntimeFactsSha256,
  cvmDescriptorRuntimeAuthoritySha256,
  cvmDescriptorRuntimeFactsSha256,
  normalizeCvmDescriptorRuntimeAuthority,
} from "./cvm-descriptor-runtime-authority-v2-core.mjs";
import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_SECRET_PHASES,
} from "./cvm-launch-intent-core.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
} from "./cvm-release-descriptor-set-constants-v3.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";
import {
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";

export const CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256 =
  `sha256:${"91".repeat(32)}`;

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

function currentRuntimeAuthorityFromLegacyFixture(legacyAuthority) {
  const raw = structuredClone(
    legacyAuthority.cvm_descriptor_runtime_authority,
  );
  const main = raw.descriptors.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  const oracle = main.service_images.find(
    ({ service }) => service === "oracle",
  );
  const delegate = main.service_images.find(
    ({ service }) => service === "delegate",
  );
  const insertAfter = (service, entry) => {
    const index = main.service_images.findIndex(
      ({ service: currentService }) => currentService === service,
    );
    if (index < 0) {
      throw new Error(`legacy main descriptor is missing ${service}`);
    }
    main.service_images.splice(index + 1, 0, entry);
  };
  insertAfter("diligence-policy-init", {
    service: "tinker-customer-authority-init",
    image: delegate.image,
  });
  insertAfter("compute-execution-worker", {
    service: "collaboration-execution-worker",
    image: delegate.image,
  });
  insertAfter("collaboration-execution-worker", {
    service: "review-operations",
    image: delegate.image,
  });
  main.service_images.push(
    { service: "mailbox-genesis", image: oracle.image },
    { service: "tinker-account-genesis", image: delegate.image },
  );
  const currentMainPolicy =
    CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm;
  main.allowed_environment_keys = [
    ...currentMainPolicy.exact_allowed_environment_keys,
  ];
  main.allowed_environment_keys_sha256 =
    currentMainPolicy.exact_allowed_environment_keys_sha256;
  main.descriptor_environment_keys = [...new Set([
    ...currentMainPolicy.exact_allowed_environment_keys.filter(
      (key) => key !== "COMPOSE_PROFILES",
    ),
    ...currentMainPolicy.public_environment_key_classification
      .descriptor_defaulted_keys,
  ])].sort();
  main.phase_policy = currentPhasePolicy(currentMainPolicy);
  main.privacy_policy = currentPrivacyPolicy(currentMainPolicy);
  main.runtime_facts_sha256 =
    cvmDescriptorDomainRuntimeFactsSha256(main);
  raw.schema = CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA;
  raw.descriptor_set_receipt_schema =
    CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA;
  raw.tinker_account_binding_ceremony_receipt_sha256 =
    CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256;
  raw.descriptor_runtime_facts_sha256 =
    cvmDescriptorRuntimeFactsSha256(raw);
  return normalizeCvmDescriptorRuntimeAuthority(raw);
}

export function syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture(
  options = {},
) {
  const legacy =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture(options);
  const runtime = currentRuntimeAuthorityFromLegacyFixture(legacy);
  const raw = structuredClone(legacy);
  raw.schema = PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA;
  raw.cvm_descriptor_runtime_authority = runtime;
  raw.cvm_descriptor_runtime_authority_sha256 =
    cvmDescriptorRuntimeAuthoritySha256(runtime);
  raw.tinker_account_binding_ceremony_receipt_sha256 =
    runtime.tinker_account_binding_ceremony_receipt_sha256;
  return normalizePhalaSevenCvmReleaseVerificationAuthority(raw);
}
