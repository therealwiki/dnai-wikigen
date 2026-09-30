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

// Pre-transform runtime v2 is a historical replay format. It includes the
// Collaboration/customer services but predates renewable recipient evidence.
// Derive only its consumed policy fields, exclude that exact later addition,
// and pin the entire result. Future current-policy changes must be explicitly
// accounted for; they cannot silently rotate persisted v2/v4 authority bytes.
const CURRENT_ONLY_KEYS_BY_DOMAIN = Object.freeze({
  main_runtime_cvm: Object.freeze([
    "TINKER_ARTIFACT_RECIPIENT_QVL_AUTH_TOKEN",
    "TINKER_ARTIFACT_RECIPIENT_QVL_URL",
    "TINKER_ARTIFACT_RECIPIENT_TRUST_JSON",
    "TINKER_ARENA_RECIPIENT_QVL_AUTH_TOKEN",
    "TINKER_ARENA_RECIPIENT_QVL_URL",
    "TINKER_ARENA_RECIPIENT_TRUST_JSON",
  ]),
  diligence_qvl_cvm: Object.freeze([
    "TINKER_ARTIFACT_RECIPIENT_QVL_AUTH_TOKEN",
  ]),
  arena_qvl_cvm: Object.freeze([
    "TINKER_ARENA_RECIPIENT_QVL_AUTH_TOKEN",
  ]),
});

const POLICY_PROJECTION_DOMAIN =
  "dnai-wikigen/cvm-descriptor-runtime-authority/v2-policy-projection/v1\0";
const POLICY_PROJECTION_KAT =
  "sha256:c5680d3a339bb1f5ef8e440645b58309a6ea832fc815ee9affa1beeb9b4f5e1c";

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function historicalV2PolicyProjection(domain) {
  const current = CURRENT_CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const isHistoricalKey = (key) =>
    !CURRENT_ONLY_KEYS_BY_DOMAIN[domain]?.includes(key);
  const allowed = current.exact_allowed_environment_keys.filter(isHistoricalKey);
  return {
    exact_allowed_environment_keys: allowed,
    exact_allowed_environment_keys_sha256:
      cvmLaunchEnvironmentKeysDigest(allowed),
    public_environment_key_classification: {
      descriptor_defaulted_keys:
        current.public_environment_key_classification
          .descriptor_defaulted_keys.filter(isHistoricalKey),
    },
    launch_settings: {
      initial_phase: current.launch_settings.initial_phase,
      initial_services: [...current.launch_settings.initial_services],
      initially_enabled_profiles: [
        ...current.launch_settings.initially_enabled_profiles,
      ],
      initially_disabled_profiles: [
        ...current.launch_settings.initially_disabled_profiles,
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
        current.encrypted_secret_environment_keys_by_phase[phase]
          .filter(isHistoricalKey),
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
      historicalV2PolicyProjection(domain),
    ]),
  ),
}, { label: "CVM descriptor runtime-authority v2 policy projection" });

export const CVM_DESCRIPTOR_RUNTIME_AUTHORITY_V2_POLICY_PROJECTION_SHA256 =
  `sha256:${createHash("sha256")
    .update(POLICY_PROJECTION_DOMAIN, "utf8")
    .update(`${JSON.stringify(sortedObject(PROJECTION), null, 2)}\n`, "utf8")
    .digest("hex")}`;

if (CVM_DESCRIPTOR_RUNTIME_AUTHORITY_V2_POLICY_PROJECTION_SHA256
    !== POLICY_PROJECTION_KAT) {
  throw new Error("CVM descriptor runtime-authority v2 policy projection drifted");
}

export const CVM_LAUNCH_DESCRIPTOR_FILES = PROJECTION.descriptor_files;
export const CVM_LAUNCH_DESCRIPTOR_POLICY = PROJECTION.policy;
export const CVM_LAUNCH_DOMAINS = PROJECTION.domains;
export const CVM_LAUNCH_SECRET_PHASES = PROJECTION.secret_phases;
export const PHALA_CVM_APP_COMPOSE_NAMES = PROJECTION.app_compose_names;
