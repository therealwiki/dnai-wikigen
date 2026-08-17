#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  createDraftCvmLaunchIntentCore,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
} from "./cvm-launch-intent-core.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const TEMPLATE_PATH = path.join(
  ROOT,
  "deployments",
  "cvm-launch-intent-core.template.json",
);
const SCHEMA_PATH = path.join(
  ROOT,
  "deployments",
  "cvm-launch-intent-core.schema.json",
);

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((entry) => sortedObject(entry));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function jsonText(value, { sortKeys = false } = {}) {
  const normalized = sortKeys ? sortedObject(value) : value;
  return `${JSON.stringify(normalized, null, 2)}\n`;
}

export async function syncCvmLaunchStaticArtifacts() {
  const draft = createDraftCvmLaunchIntentCore();
  const schema = JSON.parse(await readFile(SCHEMA_PATH, "utf8"));
  const prefixItems = schema.properties.descriptors.prefixItems;
  if (!Array.isArray(prefixItems) || prefixItems.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("tracked launch schema does not contain seven descriptor slots");
  }

  for (const [index, domain] of CVM_LAUNCH_DOMAINS.entries()) {
    const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
    const descriptor = draft.descriptors[index];
    const properties = prefixItems[index].properties;
    if (descriptor.trust_domain !== domain || properties.trust_domain.const !== domain) {
      throw new Error(`launch schema descriptor order drifted at ${domain}`);
    }
    properties.launch_settings.const = policy.launch_settings;
    properties.public_environment_key_classification.const =
      policy.public_environment_key_classification;
    properties.public_environment_value_authority.const =
      policy.public_environment_value_authority;
    properties.encrypted_secret_environment_keys_by_phase.const =
      policy.encrypted_secret_environment_keys_by_phase;
    properties.exact_allowed_environment_keys.const =
      policy.exact_allowed_environment_keys;
    properties.exact_allowed_environment_keys_sha256.const =
      policy.exact_allowed_environment_keys_sha256;
    properties.app_compose_candidate.properties.allowed_envs_count.const =
      descriptor.app_compose_candidate.allowed_envs_count;
    properties.app_compose_candidate.properties.allowed_envs_sha256.const =
      descriptor.app_compose_candidate.allowed_envs_sha256;
  }

  await writeFile(TEMPLATE_PATH, jsonText(draft, { sortKeys: true }), "utf8");
  await writeFile(SCHEMA_PATH, jsonText(schema), "utf8");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await syncCvmLaunchStaticArtifacts();
}
