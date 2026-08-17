import { createHash } from "node:crypto";

import {
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_LAUNCH_DESCRIPTOR_FILES as CURRENT_CVM_LAUNCH_DESCRIPTOR_FILES,
  CVM_LAUNCH_DESCRIPTOR_POLICY as CURRENT_CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS as CURRENT_CVM_LAUNCH_DOMAINS,
  CVM_LAUNCH_SECRET_PHASES as CURRENT_CVM_LAUNCH_SECRET_PHASES,
  PHALA_CVM_APP_COMPOSE_NAMES as CURRENT_PHALA_CVM_APP_COMPOSE_NAMES,
  cvmLaunchEnvironmentKeysDigest,
} from "./cvm-launch-intent-core.mjs";

// Runtime-authority v1 is a replay format. It predates the current
// Collaboration/customer late-input projection, so those current-only keys
// must not silently rotate persisted v1 authority bytes. This adapter derives
// the exact final v1 projection and then pins the whole projection with one KAT.
// Any future launch-policy change therefore fails closed here until it is
// explicitly versioned or accounted for; it can never silently alter v1.
const CURRENT_ONLY_MAIN_RUNTIME_KEYS = Object.freeze([
  "TINKER_COLLABORATION_ENABLED",
  "TINKER_COLLABORATION_EXECUTION_ENABLED",
  "TINKER_COLLABORATION_EXECUTION_RELEASE_GIT_SHA",
  "TINKER_COLLABORATION_EXECUTION_RELEASE_VERIFICATION_SHA256",
  "TINKER_COLLABORATION_EXECUTION_ROYALTY_RESERVATION_SAFETY_SECONDS",
  "TINKER_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED",
  "TINKER_CUSTOMER_AUTHORITY_B64",
  "TINKER_CUSTOMER_AUTHORITY_SHA256",
  "TINKER_CUSTOMER_ENABLED",
]);
const CURRENT_ONLY_MAIN_RUNTIME_KEY_PREFIXES = Object.freeze([
  "ORACLE_REVIEW_",
  "TINKER_REVIEW_OPERATIONS_",
  "TINKER_ROYALTY_",
]);
const CURRENT_ONLY_MAIN_RUNTIME_INITIAL_SERVICES = Object.freeze([
  "tinker-customer-authority-init",
]);
const CURRENT_ONLY_MAIN_RUNTIME_DISABLED_PROFILES = Object.freeze([
  "collaboration-execution",
  "review-operations",
]);

const POLICY_PROJECTION_DOMAIN =
  "dnai-wikigen/cvm-descriptor-runtime-authority/v1-policy-projection/v1\0";
const POLICY_PROJECTION_KAT =
  "sha256:172c2af4f6cabf96767ecd1544d58168685f8a5996714dffcc553b3c90215b17";

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function currentOnlyMainRuntimeKey(key) {
  return CURRENT_ONLY_MAIN_RUNTIME_KEYS.includes(key)
    || CURRENT_ONLY_MAIN_RUNTIME_KEY_PREFIXES.some(
      (prefix) => key.startsWith(prefix),
    );
}

function currentV1PolicyProjection(domain) {
  const current = CURRENT_CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const allowed = current.exact_allowed_environment_keys.filter(
    (key) => domain !== "main_runtime_cvm"
      || !currentOnlyMainRuntimeKey(key),
  );
  return {
    exact_allowed_environment_keys: allowed,
    exact_allowed_environment_keys_sha256:
      cvmLaunchEnvironmentKeysDigest(allowed),
    public_environment_key_classification: {
      descriptor_defaulted_keys: [
        ...current.public_environment_key_classification
          .descriptor_defaulted_keys.filter(
            (key) => domain !== "main_runtime_cvm"
              || !currentOnlyMainRuntimeKey(key),
          ),
      ],
    },
    launch_settings: {
      initial_phase: current.launch_settings.initial_phase,
      initial_services: current.launch_settings.initial_services.filter(
        (service) => domain !== "main_runtime_cvm"
          || !CURRENT_ONLY_MAIN_RUNTIME_INITIAL_SERVICES.includes(service),
      ),
      initially_enabled_profiles: [
        ...current.launch_settings.initially_enabled_profiles,
      ],
      initially_disabled_profiles: [
        ...current.launch_settings.initially_disabled_profiles.filter(
          (profile) => domain !== "main_runtime_cvm"
            || !CURRENT_ONLY_MAIN_RUNTIME_DISABLED_PROFILES.includes(profile),
        ),
      ],
      fresh_cvm_required: current.launch_settings.fresh_cvm_required,
      fresh_cli_deploy_forbidden:
        current.launch_settings.fresh_cli_deploy_forbidden,
      deployment_flags: {
        no_dev_os: current.launch_settings.deployment_flags.no_dev_os,
      },
      post_create_assertions: {
        listed: current.launch_settings.post_create_assertions.listed,
      },
    },
    encrypted_secret_environment_keys_by_phase: Object.fromEntries(
      CURRENT_CVM_LAUNCH_SECRET_PHASES.map((phase) => [
        phase,
        [
          ...current.encrypted_secret_environment_keys_by_phase[phase].filter(
            (key) => domain !== "main_runtime_cvm"
              || !currentOnlyMainRuntimeKey(key),
          ),
        ],
      ]),
    ),
    app_compose_candidate: {
      public_logs: current.app_compose_candidate.public_logs,
      public_sysinfo: current.app_compose_candidate.public_sysinfo,
      public_tcbinfo: current.app_compose_candidate.public_tcbinfo,
      kms_enabled: current.app_compose_candidate.kms_enabled,
      gateway_enabled: current.app_compose_candidate.gateway_enabled,
      secure_time: current.app_compose_candidate.secure_time,
      tproxy_enabled: current.app_compose_candidate.tproxy_enabled,
      storage_fs: current.app_compose_candidate.storage_fs,
    },
  };
}

const PROJECTION = deepFreezeCanonicalPlainDataGraph({
  descriptor_files: structuredClone(CURRENT_CVM_LAUNCH_DESCRIPTOR_FILES),
  domains: [...CURRENT_CVM_LAUNCH_DOMAINS],
  secret_phases: [...CURRENT_CVM_LAUNCH_SECRET_PHASES],
  app_compose_names: structuredClone(CURRENT_PHALA_CVM_APP_COMPOSE_NAMES),
  policy: Object.fromEntries(
    CURRENT_CVM_LAUNCH_DOMAINS.map((domain) => [
      domain,
      currentV1PolicyProjection(domain),
    ]),
  ),
}, { label: "CVM descriptor runtime-authority v1 policy projection" });

export const CVM_DESCRIPTOR_RUNTIME_AUTHORITY_V1_POLICY_PROJECTION_SHA256 =
  `sha256:${createHash("sha256")
    .update(POLICY_PROJECTION_DOMAIN, "utf8")
    .update(
      `${JSON.stringify(sortedObject(PROJECTION), null, 2)}\n`,
      "utf8",
    )
    .digest("hex")}`;

if (CVM_DESCRIPTOR_RUNTIME_AUTHORITY_V1_POLICY_PROJECTION_SHA256
    !== POLICY_PROJECTION_KAT) {
  throw new Error(
    "CVM descriptor runtime-authority v1 policy projection drifted",
  );
}

export const CVM_LAUNCH_DESCRIPTOR_FILES = PROJECTION.descriptor_files;
export const CVM_LAUNCH_DESCRIPTOR_POLICY = PROJECTION.policy;
export const CVM_LAUNCH_DOMAINS = PROJECTION.domains;
export const CVM_LAUNCH_SECRET_PHASES = PROJECTION.secret_phases;
export const PHALA_CVM_APP_COMPOSE_NAMES = PROJECTION.app_compose_names;
