import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";

export const PHALA_APP_COMPOSE_PRE_TRANSFORM_KEYS = Object.freeze([
  "name", "manifest_version", "runner", "docker_compose_file", "kms_enabled",
  "gateway_enabled", "secure_time", "storage_fs", "tproxy_enabled",
  "public_logs", "public_sysinfo", "public_tcbinfo", "allowed_envs",
]);
export const PHALA_APP_COMPOSE_WIRE_KEYS = Object.freeze(
  PHALA_APP_COMPOSE_PRE_TRANSFORM_KEYS.filter((key) => key !== "tproxy_enabled"),
);

/** Local expected semantics only; authenticated staging must prove server equality. */
export const PHALA_APP_COMPOSE_WIRE_HASH_SEMANTICS = Object.freeze({
  schema: "dnai.phala-app-compose-wire-hash-semantics.v1",
  sdk_package: "@phala/cloud",
  sdk_version: "0.4.0",
  transform_function: "handleGatewayCompatibility",
  transform_rule: "both_gateway_and_tproxy_boolean_delete_only_tproxy_enabled",
  pre_transform_hash: "audit_only_not_runtime_compose_identity",
  runtime_hash_input: "exact_post_transform_compose_file",
  hash_algorithm: "recursive_lexical_key_sort_compact_json_utf8_sha256_bare_lowercase_hex",
  hash_normalize: false,
  server_defaults_assumed: false,
  authenticated_staging_server_hash_equality_required: true,
});

function fail(message) {
  throw new Error(`Phala AppCompose: ${message}`);
}

function normalized(value, wire) {
  assertCanonicalPlainDataGraph(value, {
    label: "Phala AppCompose", maximumDepth: 4, maximumNodes: 1_024,
  });
  const keys = wire ? PHALA_APP_COMPOSE_WIRE_KEYS : PHALA_APP_COMPOSE_PRE_TRANSFORM_KEYS;
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    fail("fields are not exact for the reviewed pre-transform or wire shape");
  }
  if (typeof value.name !== "string" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(value.name)
    || value.manifest_version !== 2 || value.runner !== "docker-compose"
    || typeof value.docker_compose_file !== "string"
    || Buffer.byteLength(value.docker_compose_file, "utf8") < 1
    || Buffer.byteLength(value.docker_compose_file, "utf8") > 200 * 1024
    || value.kms_enabled !== true || value.gateway_enabled !== true
    || value.secure_time !== true || value.storage_fs !== "ext4"
    || (!wire && value.tproxy_enabled !== false)
    || value.public_logs !== false || value.public_sysinfo !== false || value.public_tcbinfo !== false) {
    fail("does not match the exact reviewed production posture");
  }
  if (!Array.isArray(value.allowed_envs) || value.allowed_envs.length > 512
    || value.allowed_envs.some((key) => typeof key !== "string" || !/^[A-Z][A-Z0-9_]{0,127}$/.test(key))
    || new Set(value.allowed_envs).size !== value.allowed_envs.length
    || JSON.stringify(value.allowed_envs) !== JSON.stringify([...value.allowed_envs].sort())) {
    fail("allowed_envs must be a bounded sorted unique canonical key set");
  }
  return deepFreezeCanonicalPlainDataGraph(Object.fromEntries(keys.map((key) => [
    key, key === "allowed_envs" ? [...value.allowed_envs] : value[key],
  ])), { label: "normalized Phala AppCompose" });
}

export function normalizePhalaPreTransformAppCompose(value) {
  return normalized(value, false);
}

export function normalizePhalaWireAppCompose(value) {
  return normalized(value, true);
}

export function projectPhalaAppComposeWire(value) {
  const pre = normalizePhalaPreTransformAppCompose(value);
  const wire = Object.fromEntries(PHALA_APP_COMPOSE_WIRE_KEYS.map((key) => [key, pre[key]]));
  return normalizePhalaWireAppCompose(wire);
}

function hash(value) {
  // The exact supported shape contains primitive members plus one string array;
  // its top-level lexical sort is also the recursive lexical sort.
  return createHash("sha256").update(JSON.stringify(Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, value[key]]),
  )), "utf8").digest("hex");
}

/** Historical candidate/audit meaning: no SDK or server normalization. */
export function phalaAppComposePreTransformHash(value) {
  return hash(normalizePhalaPreTransformAppCompose(value));
}

/** Expected runtime identity; never substitutes for the staging server receipt. */
export function phalaAppComposeExpectedRuntimeHash(value) {
  return hash(projectPhalaAppComposeWire(value));
}

export function phalaWireAppComposeHash(value) {
  return hash(normalizePhalaWireAppCompose(value));
}
