import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_EXECUTOR_STATE_SCHEMA,
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import {
  PHALA_EXECUTION_ORDER,
  assertProductionCvmPosture,
  assertSecretFreeExecutorStructure,
} from "./phala-production-posture-core.mjs";
import {
  assertVerifiedPhalaNonLiveBootstrapImmediateRecheck,
} from "./phala-nonlive-bootstrap-authorization.mjs";
import {
  assertFreshProductionFinalizedReadiness,
  productionFinalizedReadinessSha256,
} from "./phala-production-finalized-readiness.mjs";
import {
  assertDurablyPersistedProductionExecutionReplay,
} from "./phala-production-execution-replay.mjs";

export {
  PHALA_EXECUTOR_STATE_DOMAIN,
  PHALA_EXECUTOR_STATE_SCHEMA,
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
export const PHALA_FINALIZED_MUTATION_GATE_SCHEMA =
  "dnai.phala-finalized-mutation-gate.v1";
export const PHALA_FINALIZED_MUTATION_GATE_DOMAIN =
  "dnai-wikigen/phala-finalized-mutation-gate/v1\0";
export const PHALA_SIGNED_ENV_KEY_BINDING_SCHEMA =
  "dnai.phala-signed-env-key-binding.v1";
export const PHALA_PROVENANCE_VERIFIED_EXECUTOR_COMPLETION_PRODUCER_STATUS =
  "production_executor_requires_durable_journal_finalized_gates_authenticated_sdk_observations_internal_times_and_release_replay_state";
export {
  PHALA_EXECUTION_ORDER,
  assertProductionCvmPosture,
  assertSecretFreeExecutorStructure,
};
export const PHALA_EXACT_SDK_CALL_SEQUENCE = Object.freeze([
  "getCurrentUser",
  "getCvmCreateResources",
  "getOsImages",
  "getKmsList",
  "getKmsInfo",
  "nextAppIds",
  "provisionCvm:supporting-six-then-main",
  "getAppEnvEncryptPubKey:first-pass-all-seven",
  "getAppEnvEncryptPubKey:immediate-refetch-before-each-commit",
  "commitCvmProvision:supporting-six-then-main",
  "getCvmInfo:all-seven",
  "getCvmAttestation:all-seven",
]);

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const UUID_OR_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const ENVIRONMENT_KEY = /^[A-Z][A-Z0-9_]{0,127}$/;
const INSTANCE_TYPE = /^[a-z][a-z0-9.-]{1,63}$/;
const COMPRESSED_K256 = /^0x0[23][0-9a-f]{64}$/;
const PUBLIC_KEY = /^(?!0{64}$)[0-9a-f]{64}$/;
const SIGNATURE = /^[0-9a-f]{130}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MAX_COMPOSE_BYTES = 200 * 1024;
const FINALIZED_MUTATION_GATES = new WeakSet();
const PRODUCTION_FINALIZED_MUTATION_GATES = new WeakMap();
// Populated only by the production executor registrar after it has replayed
// one durably persisted terminal journal against branded production mutation
// gates and authenticated pinned-SDK observations. Pure state normalization is
// never sufficient provenance.
const PROVENANCE_VERIFIED_COMPLETED_STATES = new WeakMap();

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    throw new Error(`${label} must contain exactly the allowed fields`);
  }
  return value;
}

function exactDigest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactBareDigest(value, label) {
  if (typeof value !== "string" || !BARE_SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero bare SHA-256 digest`);
  }
  return value;
}

function exactAppId(value, label) {
  if (typeof value !== "string") throw new Error(`${label} is invalid`);
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  if (!APP_ID.test(normalized)) throw new Error(`${label} must be exactly 20 nonzero bytes`);
  return normalized;
}

function exactIdentifier(value, label) {
  if (typeof value !== "string" || !UUID_OR_ID.test(value)) {
    throw new Error(`${label} must be a canonical bounded identifier`);
  }
  return value;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((entry) => sortedObject(entry));
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalCompact(value) {
  return JSON.stringify(sortedObject(value), (key, entry) => (
    typeof entry === "number" && !Number.isFinite(entry) ? null : entry
  ));
}

function canonicalTimestamp(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)
    || new Date(parsed).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must round-trip as a canonical UTC second`);
  }
  return value;
}

function sortedUniqueEnvironmentKeys(keys, label) {
  if (!Array.isArray(keys) || keys.length > 512) {
    throw new Error(`${label} must be a bounded array`);
  }
  const normalized = keys.map((key, index) => {
    if (typeof key !== "string" || !ENVIRONMENT_KEY.test(key)) {
      throw new Error(`${label}[${index}] is not a canonical environment key`);
    }
    return key;
  });
  const sorted = [...new Set(normalized)].sort();
  if (sorted.length !== normalized.length
    || JSON.stringify(sorted) !== JSON.stringify(normalized)) {
    throw new Error(`${label} must be sorted and duplicate-free`);
  }
  return sorted;
}

export function dstackCanonicalComposeHash(appCompose) {
  if (!isRecord(appCompose)) throw new Error("AppCompose must be an object");
  return createHash("sha256")
    .update(Buffer.from(canonicalCompact(appCompose), "utf8"))
    .digest("hex");
}

export function cloudLegacyPrettyComposeHashForRejection(appCompose) {
  if (!isRecord(appCompose)) throw new Error("AppCompose must be an object");
  const serialized = JSON.stringify(sortedObject(appCompose), null, 4).replace(/": /g, '":');
  return createHash("sha256").update(Buffer.from(serialized, "utf8")).digest("hex");
}

export function buildExplicitAppCompose({
  profile,
  dockerComposeFile,
  allowedEnvironmentKeys,
} = {}) {
  const parsed = exactRecord(profile, [
    "name",
    "manifest_version",
    "runner",
    "kms_enabled",
    "gateway_enabled",
    "tproxy_enabled",
    "skip_gateway",
    "storage_fs",
    "secure_time",
    "public_logs",
    "public_sysinfo",
    "public_tcbinfo",
  ], "AppCompose profile");
  if (parsed.manifest_version !== 2 || parsed.runner !== "docker-compose"
    || parsed.kms_enabled !== true || typeof parsed.gateway_enabled !== "boolean"
    || parsed.tproxy_enabled !== false
    || parsed.skip_gateway !== !parsed.gateway_enabled
    || parsed.storage_fs !== "ext4" || parsed.secure_time !== true
    || parsed.public_logs !== false || parsed.public_sysinfo !== false
    || parsed.public_tcbinfo !== false) {
    throw new Error("AppCompose profile leaves an implicit or unsafe platform default");
  }
  exactIdentifier(parsed.name, "AppCompose name");
  if (typeof dockerComposeFile !== "string"
    || Buffer.byteLength(dockerComposeFile, "utf8") < 1
    || Buffer.byteLength(dockerComposeFile, "utf8") > MAX_COMPOSE_BYTES) {
    throw new Error("Docker Compose descriptor is empty or exceeds 200 KiB");
  }
  const allowedEnvs = sortedUniqueEnvironmentKeys(
    allowedEnvironmentKeys,
    "allowed_envs",
  );
  return {
    name: parsed.name,
    manifest_version: 2,
    runner: "docker-compose",
    kms_enabled: true,
    gateway_enabled: parsed.gateway_enabled,
    tproxy_enabled: false,
    storage_fs: "ext4",
    secure_time: true,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
    allowed_envs: allowedEnvs,
    docker_compose_file: dockerComposeFile,
  };
}

export function buildExactProvisionRequest({
  domain,
  applicationName,
  resourceTarget,
  appCompose,
  activeEnvironmentKeys,
  appId,
  nonce,
  kmsId,
} = {}) {
  if (!PHALA_EXECUTION_ORDER.includes(domain)) throw new Error("unknown CVM launch domain");
  const resource = exactRecord(resourceTarget, [
    "authority_status",
    "instance_type",
    "disk_size",
    "placement",
  ], "resource target");
  const placement = exactRecord(resource.placement, [
    "selection_mode",
    "node_id",
    "region",
  ], "resource target placement");
  if (resource.authority_status !== "reviewed_authenticated_catalog_and_quota_validated"
    || typeof resource.instance_type !== "string"
    || !INSTANCE_TYPE.test(resource.instance_type)
    || !Number.isSafeInteger(resource.disk_size) || resource.disk_size < 20
    || resource.disk_size > 16_384
    || placement.selection_mode !== "automatic_best_match"
    || placement.node_id !== null || placement.region !== null) {
    throw new Error("resource target is not exact reviewed automatic placement authority");
  }
  const canonicalAppId = exactAppId(appId, "predicted app id");
  if (!Number.isSafeInteger(nonce) || nonce < 0) throw new Error("predicted nonce is invalid");
  const envKeys = sortedUniqueEnvironmentKeys(activeEnvironmentKeys, "active env_keys");
  if (!isRecord(appCompose)
    || appCompose.public_logs !== false || appCompose.public_sysinfo !== false
    || appCompose.public_tcbinfo !== false
    || appCompose.kms_enabled !== true || appCompose.runner !== "docker-compose") {
    throw new Error("exact explicit AppCompose is required");
  }
  return {
    name: exactIdentifier(applicationName, "application name"),
    instance_type: resource.instance_type,
    disk_size: resource.disk_size,
    image: PHALA_OS_IMAGE_CATALOG_ENTRY.name,
    compose_file: structuredClone(appCompose),
    listed: false,
    kms_id: exactIdentifier(kmsId, "KMS id"),
    key_provider_mode: "kms",
    skip_gateway: appCompose.gateway_enabled !== true,
    env_keys: envKeys,
    nonce,
    app_id: canonicalAppId,
  };
}

export function normalizeSignedEnvironmentKeyResponse(value) {
  const parsed = exactRecord(value, ["public_key", "signature"], "signed env key response");
  const publicKey = typeof parsed.public_key === "string"
    ? parsed.public_key.replace(/^0x/, "").toLowerCase()
    : "";
  const signature = typeof parsed.signature === "string"
    ? parsed.signature.replace(/^0x/, "").toLowerCase()
    : "";
  if (!PUBLIC_KEY.test(publicKey) || !SIGNATURE.test(signature)) {
    throw new Error("signed env key response has an invalid key or signature length");
  }
  const recovery = Number.parseInt(signature.slice(-2), 16);
  if (recovery !== 0 && recovery !== 1) {
    throw new Error("signed env key signature recovery bit is invalid");
  }
  return { public_key: publicKey, signature };
}

export function assertRecoveredSignedEnvironmentKey({
  appId,
  response,
  recoveredSigner,
  pinnedSigner,
} = {}) {
  const canonicalAppId = exactAppId(appId, "signed env key app id");
  const normalized = normalizeSignedEnvironmentKeyResponse(response);
  if (typeof pinnedSigner !== "string" || !COMPRESSED_K256.test(pinnedSigner)
    || typeof recoveredSigner !== "string"
    || recoveredSigner.toLowerCase() !== pinnedSigner) {
    throw new Error("signed env key does not recover the independently pinned KMS signer");
  }
  return {
    schema: PHALA_SIGNED_ENV_KEY_BINDING_SCHEMA,
    app_id: canonicalAppId,
    public_key: normalized.public_key,
    public_key_sha256: `sha256:${createHash("sha256")
      .update(Buffer.from(normalized.public_key, "hex"))
      .digest("hex")}`,
    signer_k256: pinnedSigner,
    signature_verified: true,
    legacy_signature_has_no_timestamp: true,
  };
}

export function assertImmediateSignedEnvironmentKeyRefetch(first, second) {
  const left = exactRecord(first, [
    "schema",
    "app_id",
    "public_key",
    "public_key_sha256",
    "signer_k256",
    "signature_verified",
    "legacy_signature_has_no_timestamp",
  ], "first signed key binding");
  const right = exactRecord(second, Object.keys(left), "refetched signed key binding");
  if (JSON.stringify(left) !== JSON.stringify(right)) {
    throw new Error("immediate signed env key refetch changed app, key, or signer binding");
  }
  return structuredClone(left);
}

export function assertPairwiseDistinctSignedEnvironmentKeys(bindings) {
  if (!Array.isArray(bindings) || bindings.length !== PHALA_EXECUTION_ORDER.length) {
    throw new Error("exactly seven signed env key bindings are required");
  }
  const appIds = bindings.map(({ app_id: appId }) => exactAppId(appId, "binding app id"));
  const publicKeys = bindings.map(({ public_key: publicKey }) => {
    if (typeof publicKey !== "string" || !PUBLIC_KEY.test(publicKey)) {
      throw new Error("binding public key is invalid");
    }
    return publicKey;
  });
  if (new Set(appIds).size !== bindings.length
    || new Set(publicKeys).size !== bindings.length) {
    throw new Error("app ids and signed env public keys must be pairwise distinct");
  }
  return true;
}

export function assertPreparedCvmObservation({
  response,
  appId,
  expectedComposeHash,
  expectedKmsId,
  expectedInstanceType,
  expectedOsImageHash = PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
} = {}) {
  if (!isRecord(response)) throw new Error("prepare response must be an object");
  const normalizedAppId = exactAppId(response.app_id, "prepare response app id");
  if (normalizedAppId !== exactAppId(appId, "expected app id")
    || response.compose_hash !== exactBareDigest(expectedComposeHash, "expected compose hash")
    || response.compose_hash !== response.compose_hash?.toLowerCase()
    || response.kms_id !== expectedKmsId
    || response.instance_type !== expectedInstanceType
    || response.os_image_hash !== expectedOsImageHash) {
    throw new Error("prepare response differs from the exact reviewed request and catalogs");
  }
  const returnedKey = response.app_env_encrypt_pubkey == null
    ? null
    : normalizeSignedEnvironmentKeyResponse({
      public_key: response.app_env_encrypt_pubkey,
      signature: `${"1".repeat(128)}00`,
    }).public_key;
  return {
    app_id: normalizedAppId,
    compose_hash: response.compose_hash,
    kms_id: exactIdentifier(response.kms_id, "prepare KMS id"),
    instance_type: response.instance_type,
    os_image_hash: response.os_image_hash,
    node_id: Number.isSafeInteger(response.node_id) && response.node_id > 0
      ? response.node_id
      : null,
    device_id: response.device_id == null
      ? null
      : exactIdentifier(response.device_id, "prepare device id"),
    prepared_public_key: returnedKey,
  };
}

function normalizeFinalizedMutationGateShape(value, {
  nowMs = Date.now(),
  minimumRemainingMs = 15_000,
} = {}) {
  const gate = exactRecord(value, [
    "schema",
    "stage",
    "action",
    "batch_id",
    "bootstrap_authorization_id",
    "bootstrap_authorization_receipt_sha256",
    "bootstrap_authorization_status",
    "compatibility_receipt_sha256",
    "production_target_authority_sha256",
    "sdk_wire_transform_staging_receipt_sha256",
    "fresh_contract_deployment_receipt_sha256",
    "release_manifest_sigstore_verification_receipt_sha256",
    "release_manifest_sha256",
    "descriptor_set_receipt_sha256",
    "execution_policy_anchor_address",
    "execution_policy_anchor_deployment_block",
    "execution_policy_anchor_deployment_block_hash",
    "target_authority_expires_at",
    "domain",
    "readiness_sha256",
    "snapshot_finality",
    "snapshot_block_number",
    "snapshot_block_hash",
    "checked_at",
    "expires_at",
    "live_traffic_authorized",
  ], "finalized mutation gate");
  if (gate.schema !== PHALA_FINALIZED_MUTATION_GATE_SCHEMA
    || gate.stage !== "cvm_launch"
    || !["provisionCvm", "commitCvmProvision"].includes(gate.action)
    || gate.bootstrap_authorization_status
      !== "non_live_bootstrap_signatures_verified"
    || gate.live_traffic_authorized !== false
    || !PHALA_EXECUTION_ORDER.includes(gate.domain)
    || gate.snapshot_finality !== "rpc_finalized"
    || !Number.isSafeInteger(gate.snapshot_block_number)
    || gate.snapshot_block_number < 1
    || typeof gate.execution_policy_anchor_address !== "string"
    || !ADDRESS.test(gate.execution_policy_anchor_address)
    || !Number.isSafeInteger(gate.execution_policy_anchor_deployment_block)
    || gate.execution_policy_anchor_deployment_block < 1
    || typeof gate.execution_policy_anchor_deployment_block_hash !== "string"
    || !BYTES32.test(gate.execution_policy_anchor_deployment_block_hash)
    || typeof gate.snapshot_block_hash !== "string"
    || !BYTES32.test(gate.snapshot_block_hash)) {
    throw new Error("mutation gate is not bound to one exact finalized CVM launch action");
  }
  const checkedAt = canonicalTimestamp(gate.checked_at, "mutation gate checked_at");
  const expiresAt = canonicalTimestamp(gate.expires_at, "mutation gate expires_at");
  const targetExpiresAt = canonicalTimestamp(
    gate.target_authority_expires_at,
    "mutation gate target_authority_expires_at",
  );
  if (!Number.isSafeInteger(nowMs) || minimumRemainingMs < 1
    || Date.parse(checkedAt) > nowMs + 1_000
    || Date.parse(expiresAt) - nowMs < minimumRemainingMs
    || Date.parse(expiresAt) > Date.parse(targetExpiresAt)) {
    throw new Error("finalized mutation gate is stale or lacks mutation headroom");
  }
  return {
    ...gate,
    batch_id: exactDigest(gate.batch_id, "mutation gate batch_id"),
    bootstrap_authorization_id: exactDigest(
      gate.bootstrap_authorization_id,
      "mutation gate bootstrap_authorization_id",
    ),
    bootstrap_authorization_receipt_sha256: exactDigest(
      gate.bootstrap_authorization_receipt_sha256,
      "mutation gate bootstrap authorization receipt",
    ),
    compatibility_receipt_sha256: exactDigest(
      gate.compatibility_receipt_sha256,
      "mutation gate compatibility receipt",
    ),
    production_target_authority_sha256: exactDigest(
      gate.production_target_authority_sha256,
      "mutation gate production target authority",
    ),
    sdk_wire_transform_staging_receipt_sha256: exactDigest(
      gate.sdk_wire_transform_staging_receipt_sha256,
      "mutation gate SDK wire-transform staging receipt",
    ),
    fresh_contract_deployment_receipt_sha256: exactDigest(
      gate.fresh_contract_deployment_receipt_sha256,
      "mutation gate fresh contract deployment receipt",
    ),
    release_manifest_sigstore_verification_receipt_sha256: exactDigest(
      gate.release_manifest_sigstore_verification_receipt_sha256,
      "mutation gate release manifest Sigstore verification receipt",
    ),
    release_manifest_sha256: exactDigest(
      gate.release_manifest_sha256,
      "mutation gate release manifest",
    ),
    descriptor_set_receipt_sha256: exactDigest(
      gate.descriptor_set_receipt_sha256,
      "mutation gate descriptor set receipt",
    ),
    readiness_sha256: exactDigest(gate.readiness_sha256, "mutation readiness digest"),
    checked_at: checkedAt,
    expires_at: expiresAt,
    target_authority_expires_at: targetExpiresAt,
  };
}

export function normalizeFinalizedMutationGate(value, options = {}) {
  if (!value || !FINALIZED_MUTATION_GATES.has(value)) {
    throw new Error(
      "finalized mutation gate must be an unforgeable gate built from a stable-file bootstrap recheck",
    );
  }
  return normalizeFinalizedMutationGateShape(value, options);
}

export function createFinalizedPhalaMutationGate({
  authorizationRecheck,
  action,
  domain,
  readinessSha256,
  snapshotBlockNumber,
  snapshotBlockHash,
  checkedAt,
  expiresAt,
  nowMs = Date.now(),
  minimumRemainingMs = 15_000,
} = {}) {
  const checkpointByAction = {
    provisionCvm: "before_each_provision",
    commitCvmProvision: "before_each_commit",
  };
  const checkpoint = checkpointByAction[action];
  if (!checkpoint) {
    throw new Error("mutation action has no reviewed bootstrap recheck checkpoint");
  }
  const recheck = assertVerifiedPhalaNonLiveBootstrapImmediateRecheck({
    recheck: authorizationRecheck,
    checkpoint,
    expectedBatchId: authorizationRecheck?.batch_id,
    expectedAuthorizationId: authorizationRecheck?.authorization_id,
    requireStableFileReread: true,
    requireIndependentGenesisAnchor: true,
    requireDescriptorSetValidation: true,
    requireTargetAuthorityValidation: true,
    requireReleaseManifestSigstoreValidation: true,
  });
  if (checkedAt !== recheck.checked_at
    || Date.parse(expiresAt) > Date.parse(recheck.authorization_expires_at)
    || Date.parse(expiresAt) > Date.parse(recheck.target_authority_expires_at)) {
    throw new Error(
      "mutation gate must be co-timed with and not outlive bootstrap or target authority",
    );
  }
  const gate = Object.freeze(normalizeFinalizedMutationGateShape({
    schema: PHALA_FINALIZED_MUTATION_GATE_SCHEMA,
    stage: "cvm_launch",
    action,
    batch_id: recheck.batch_id,
    bootstrap_authorization_id: recheck.authorization_id,
    bootstrap_authorization_receipt_sha256:
      recheck.authorization_receipt_sha256,
    bootstrap_authorization_status: "non_live_bootstrap_signatures_verified",
    compatibility_receipt_sha256: recheck.compatibility_receipt_sha256,
    production_target_authority_sha256:
      recheck.production_target_authority_sha256,
    sdk_wire_transform_staging_receipt_sha256:
      recheck.sdk_wire_transform_staging_receipt_sha256,
    fresh_contract_deployment_receipt_sha256:
      recheck.fresh_contract_deployment_receipt_sha256,
    release_manifest_sigstore_verification_receipt_sha256:
      recheck.release_manifest_sigstore_verification_receipt_sha256,
    release_manifest_sha256: recheck.release_manifest_sha256,
    descriptor_set_receipt_sha256: recheck.descriptor_set_receipt_sha256,
    execution_policy_anchor_address:
      recheck.execution_policy_anchor_address,
    execution_policy_anchor_deployment_block:
      recheck.execution_policy_anchor_deployment_block,
    execution_policy_anchor_deployment_block_hash:
      recheck.execution_policy_anchor_deployment_block_hash,
    target_authority_expires_at: recheck.target_authority_expires_at,
    domain,
    readiness_sha256: readinessSha256,
    snapshot_finality: "rpc_finalized",
    snapshot_block_number: snapshotBlockNumber,
    snapshot_block_hash: snapshotBlockHash,
    checked_at: checkedAt,
    expires_at: expiresAt,
    live_traffic_authorized: false,
  }, { nowMs, minimumRemainingMs }));
  FINALIZED_MUTATION_GATES.add(gate);
  return gate;
}

/**
 * The production mutation-gate constructor accepts no caller clock, block
 * number, block hash, expiry, or readiness digest. Those values are projected
 * from one privately branded dual-RPC finalized observation and the same
 * stable-file bootstrap recheck that authorizes the exact mutation.
 */
export function createProductionFinalizedPhalaMutationGate({
  authorizationRecheck,
  action,
  domain,
  finalizedReadiness,
} = {}) {
  const readiness = assertFreshProductionFinalizedReadiness(finalizedReadiness);
  const nowMs = Date.now();
  const checkpoint = action === "provisionCvm"
    ? "before_each_provision"
    : (action === "commitCvmProvision" ? "before_each_commit" : null);
  if (!checkpoint) {
    throw new Error("production mutation action has no exact bootstrap checkpoint");
  }
  const recheck = assertVerifiedPhalaNonLiveBootstrapImmediateRecheck({
    recheck: authorizationRecheck,
    checkpoint,
    expectedBatchId: authorizationRecheck?.batch_id,
    expectedAuthorizationId: authorizationRecheck?.authorization_id,
    requireStableFileReread: true,
    requireIndependentGenesisAnchor: true,
    requireDescriptorSetValidation: true,
    requireTargetAuthorityValidation: true,
    requireReleaseManifestSigstoreValidation: true,
  });
  const expiresMs = Math.min(
    Date.parse(readiness.expires_at),
    Date.parse(recheck.authorization_expires_at),
    Date.parse(recheck.target_authority_expires_at),
  );
  const expiresAt = new Date(Math.floor(expiresMs / 1_000) * 1_000)
    .toISOString()
    .replace(/\.000Z$/, "Z");
  const gate = createFinalizedPhalaMutationGate({
    authorizationRecheck: recheck,
    action,
    domain,
    readinessSha256: productionFinalizedReadinessSha256(readiness),
    snapshotBlockNumber: readiness.common_finalized_block_number,
    snapshotBlockHash: readiness.common_finalized_block_hash,
    checkedAt: recheck.checked_at,
    expiresAt,
    nowMs,
    minimumRemainingMs: 15_000,
  });
  PRODUCTION_FINALIZED_MUTATION_GATES.set(gate, Object.freeze({
    readiness_sha256: productionFinalizedReadinessSha256(readiness),
    snapshot_block_number: readiness.common_finalized_block_number,
    snapshot_block_hash: readiness.common_finalized_block_hash,
  }));
  return gate;
}

export function assertProductionFinalizedPhalaMutationGate(value, options = {}) {
  const provenance = value && PRODUCTION_FINALIZED_MUTATION_GATES.get(value);
  if (!provenance) {
    throw new Error(
      "a production mutation gate derived from branded dual-RPC readiness is required",
    );
  }
  const gate = normalizeFinalizedMutationGate(value, options);
  if (gate.readiness_sha256 !== provenance.readiness_sha256
    || gate.snapshot_block_number !== provenance.snapshot_block_number
    || gate.snapshot_block_hash !== provenance.snapshot_block_hash) {
    throw new Error("production mutation gate readiness provenance drifted");
  }
  return value;
}

export function productionFinalizedPhalaMutationGateSha256(value, options = {}) {
  assertProductionFinalizedPhalaMutationGate(value, options);
  return `sha256:${createHash("sha256")
    .update(Buffer.from(PHALA_FINALIZED_MUTATION_GATE_DOMAIN, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(value)), "utf8"))
    .digest("hex")}`;
}

function normalizeReservation(value, index) {
  const item = exactRecord(value, ["domain", "app_id", "nonce"], `reservation[${index}]`);
  if (item.domain !== PHALA_EXECUTION_ORDER[index]
    || !Number.isSafeInteger(item.nonce) || item.nonce < 0) {
    throw new Error("app-id reservations must match exact domain order and valid nonces");
  }
  return {
    domain: item.domain,
    app_id: exactAppId(item.app_id, `reservation[${index}].app_id`),
    nonce: item.nonce,
  };
}

function nextDomain(entries) {
  return PHALA_EXECUTION_ORDER[entries.length] ?? null;
}

export function createInitialPhalaExecutorState({
  batchId,
  bootstrapAuthorizationId,
  bootstrapAuthorizationReceiptSha256,
  releaseSha,
  launchIntentSha256,
  targetAuthoritySha256,
  phalaRecoveryDirectoryIdentityAnchorSha256,
} = {}) {
  if (typeof releaseSha !== "string" || !/^[0-9a-f]{40}$/.test(releaseSha)
    || releaseSha === "0".repeat(40)) {
    throw new Error("executor release SHA is invalid");
  }
  const state = {
    schema: PHALA_EXECUTOR_STATE_SCHEMA,
    status: "initialized",
    sequence: 0,
    batch_id: exactDigest(batchId, "batch_id"),
    bootstrap_authorization_id: exactDigest(
      bootstrapAuthorizationId,
      "bootstrap_authorization_id",
    ),
    bootstrap_authorization_receipt_sha256: exactDigest(
      bootstrapAuthorizationReceiptSha256,
      "bootstrap_authorization_receipt_sha256",
    ),
    release_sha: releaseSha,
    launch_intent_sha256: exactDigest(launchIntentSha256, "launch_intent_sha256"),
    target_authority_sha256: exactDigest(
      targetAuthoritySha256,
      "target_authority_sha256",
    ),
    phala_recovery_directory_identity_anchor_sha256: exactDigest(
      phalaRecoveryDirectoryIdentityAnchorSha256,
      "phala_recovery_directory_identity_anchor_sha256",
    ),
    reservations: [],
    preparations: [],
    signed_key_bindings: [],
    committed_prefix: [],
    pending_mutation: null,
    reconciliation: null,
    posture_receipts: [],
  };
  assertSecretFreeExecutorStructure(state, "initial executor state");
  return state;
}

function advanced(state, updates) {
  const next = {
    ...structuredClone(state),
    ...updates,
    sequence: state.sequence + 1,
  };
  assertSecretFreeExecutorStructure(next, "executor state");
  return next;
}

export function transitionPhalaExecutorState(state, event) {
  if (!isRecord(state) || state.schema !== PHALA_EXECUTOR_STATE_SCHEMA
    || !isRecord(event) || typeof event.type !== "string") {
    throw new Error("executor transition requires a canonical state and event");
  }
  assertSecretFreeExecutorStructure(event, "executor event");
  if (state.status === "initialized" && event.type === "app_ids_observed") {
    if (!Array.isArray(event.reservations)
      || event.reservations.length !== PHALA_EXECUTION_ORDER.length) {
      throw new Error("exactly seven app-id reservations are required");
    }
    const reservations = event.reservations.map(normalizeReservation);
    if (new Set(reservations.map(({ app_id: appId }) => appId)).size
        !== reservations.length
      || new Set(reservations.map(({ nonce }) => nonce)).size !== reservations.length) {
      throw new Error("app-id reservations and nonces must be pairwise distinct");
    }
    return advanced(state, { status: "ready_to_prepare", reservations });
  }

  if (state.status === "ready_to_prepare" && event.type === "provision_attempt") {
    const domain = nextDomain(state.preparations);
    if (event.domain !== domain || state.pending_mutation !== null) {
      throw new Error("provision attempts must follow supporting-six-then-main order");
    }
    return advanced(state, {
      status: "provision_attempt_durable",
      pending_mutation: {
        action: "provisionCvm",
        domain,
        request_sha256: exactDigest(event.request_sha256, "provision request digest"),
        readiness_sha256: exactDigest(event.readiness_sha256, "provision readiness digest"),
        attempted_at: canonicalTimestamp(
          event.attempted_at,
          "provision attempted_at",
        ),
      },
    });
  }

  if (state.status === "provision_attempt_durable"
    && event.type === "provision_observed") {
    if (event.domain !== state.pending_mutation?.domain) {
      throw new Error("provision observation does not match the durable attempt");
    }
    const observedAt = canonicalTimestamp(
      event.observed_at,
      "provision observed_at",
    );
    if (Date.parse(observedAt) < Date.parse(state.pending_mutation.attempted_at)
      || Date.parse(observedAt) - Date.parse(state.pending_mutation.attempted_at)
        > 60_000) {
      throw new Error("provision observation time is outside the durable attempt window");
    }
    const preparations = [...state.preparations, {
      domain: event.domain,
      request_sha256: state.pending_mutation.request_sha256,
      readiness_sha256: state.pending_mutation.readiness_sha256,
      attempted_at: state.pending_mutation.attempted_at,
      observed_at: observedAt,
      observation_sha256: exactDigest(
        event.observation_sha256,
        "prepare observation digest",
      ),
    }];
    return advanced(state, {
      status: preparations.length === PHALA_EXECUTION_ORDER.length
        ? "all_preparations_observed"
        : "ready_to_prepare",
      preparations,
      pending_mutation: null,
    });
  }

  if (state.status === "all_preparations_observed"
    && event.type === "preparations_validated") {
    return advanced(state, {
      status: "collecting_signed_keys",
      preparations_validation_sha256: exactDigest(
        event.validation_sha256,
        "preparations validation digest",
      ),
    });
  }

  if (state.status === "collecting_signed_keys" && event.type === "signed_key_observed") {
    const domain = nextDomain(state.signed_key_bindings);
    if (event.domain !== domain) {
      throw new Error("signed key observations must follow exact domain order");
    }
    const bindings = [...state.signed_key_bindings, {
      domain,
      binding_sha256: exactDigest(event.binding_sha256, "signed key binding digest"),
      public_key_sha256: exactDigest(event.public_key_sha256, "signed public key digest"),
    }];
    if (new Set(bindings.map(({ public_key_sha256: digest }) => digest)).size
        !== bindings.length) {
      throw new Error("signed env public keys must be pairwise distinct");
    }
    return advanced(state, {
      status: bindings.length === PHALA_EXECUTION_ORDER.length
        ? "signed_keys_validated"
        : "collecting_signed_keys",
      signed_key_bindings: bindings,
    });
  }

  if (state.status === "signed_keys_validated" && event.type === "commit_attempt") {
    const domain = nextDomain(state.committed_prefix);
    if (event.domain !== domain || state.pending_mutation !== null) {
      throw new Error("commit attempts must follow supporting-six-then-main order");
    }
    return advanced(state, {
      status: "commit_attempt_durable",
      pending_mutation: {
        action: "commitCvmProvision",
        domain,
        request_sha256: exactDigest(event.request_sha256, "commit request digest"),
        readiness_sha256: exactDigest(event.readiness_sha256, "commit readiness digest"),
        attempted_at: canonicalTimestamp(
          event.attempted_at,
          "commit attempted_at",
        ),
      },
    });
  }

  if (state.status === "commit_attempt_durable" && event.type === "commit_observed") {
    if (event.domain !== state.pending_mutation?.domain) {
      throw new Error("commit observation does not match the durable attempt");
    }
    const observedAt = canonicalTimestamp(event.observed_at, "commit observed_at");
    if (Date.parse(observedAt) < Date.parse(state.pending_mutation.attempted_at)
      || Date.parse(observedAt) - Date.parse(state.pending_mutation.attempted_at)
        > 60_000) {
      throw new Error("commit observation time is outside the durable attempt window");
    }
    const committed = [...state.committed_prefix, {
      domain: event.domain,
      cvm_id: exactIdentifier(event.cvm_id, "committed CVM id"),
      request_sha256: state.pending_mutation.request_sha256,
      readiness_sha256: state.pending_mutation.readiness_sha256,
      attempted_at: state.pending_mutation.attempted_at,
      observed_at: observedAt,
      observation_sha256: exactDigest(
        event.observation_sha256,
        "commit observation digest",
      ),
    }];
    return advanced(state, {
      status: committed.length === PHALA_EXECUTION_ORDER.length
        ? "posture_validation_pending"
        : "signed_keys_validated",
      committed_prefix: committed,
      pending_mutation: null,
    });
  }

  if (["provision_attempt_durable", "commit_attempt_durable"].includes(state.status)
    && event.type === "mutation_outcome_ambiguous") {
    if (event.domain !== state.pending_mutation?.domain
      || event.action !== state.pending_mutation?.action) {
      throw new Error("ambiguous outcome does not match the durable pending mutation");
    }
    return advanced(state, {
      status: "ambiguous_reconcile_required",
      reconciliation: {
        status: "read_only_operator_reconciliation_required",
        reason_code: exactIdentifier(event.reason_code, "ambiguity reason code"),
        action: event.action,
        domain: event.domain,
      },
    });
  }

  if (state.status === "ambiguous_reconcile_required"
    && event.type === "reconciliation_recorded") {
    if (!Array.isArray(event.observed_committed_domains)
      || event.observed_committed_domains.some((domain, index) => (
        domain !== PHALA_EXECUTION_ORDER[index]
      ))) {
      throw new Error("reconciliation must record one exact committed prefix");
    }
    return advanced(state, {
      status: event.observed_committed_domains.length > 0
        ? "partial_commit_requires_operator_reconciliation"
        : "reconciled_no_mutation_operator_review_required",
      reconciliation: {
        status: "terminal_manual_review_no_automatic_retry_or_cleanup",
        observation_sha256: exactDigest(
          event.observation_sha256,
          "reconciliation observation digest",
        ),
        observed_committed_domains: [...event.observed_committed_domains],
      },
      pending_mutation: null,
    });
  }

  if (state.status === "posture_validation_pending"
    && event.type === "posture_validated") {
    if (!Array.isArray(event.receipts)
      || event.receipts.length !== PHALA_EXECUTION_ORDER.length) {
      throw new Error("posture validation requires exactly seven receipt digests");
    }
    const receipts = event.receipts.map((entry, index) => {
      const receipt = exactRecord(entry, ["domain", "receipt_sha256"], `posture receipt[${index}]`);
      if (receipt.domain !== PHALA_EXECUTION_ORDER[index]) {
        throw new Error("posture receipts must follow exact domain order");
      }
      return {
        domain: receipt.domain,
        receipt_sha256: exactDigest(receipt.receipt_sha256, "posture receipt digest"),
      };
    });
    return advanced(state, {
      status: "complete_seven_commits_posture_observed_attestation_unverified",
      posture_receipts: receipts,
    });
  }

  throw new Error(`illegal executor transition from ${state.status} via ${event.type}`);
}

export function assertProvenanceVerifiedCompletedPhalaExecutorState(value) {
  const expectedDigest = PROVENANCE_VERIFIED_COMPLETED_STATES.get(value);
  if (!expectedDigest) {
    throw new Error(
      "completed executor state lacks durable journal, finalized gate, authenticated SDK observation, internal-clock, and release-replay provenance",
    );
  }
  const normalized = normalizeCompletedPhalaExecutorState(value);
  if (phalaExecutorStateDigest(normalized) !== expectedDigest
    || canonicalCompact(normalized) !== canonicalCompact(value)) {
    throw new Error("provenance-verified completed executor state digest guard failed");
  }
  return value;
}

/**
 * Mint the completion provenance brand only after the private durable replay
 * module has revalidated the exact terminal journal, production gates,
 * authenticated pinned-SDK observations, and stable receipt bytes. The static
 * ESM cycle is intentional and safe: replay consumes these bindings only when
 * this function is invoked, after both modules have completed initialization.
 */
export async function registerProvenanceVerifiedCompletedPhalaExecutorState(
  options = {},
) {
  const parsed = exactRecord(options, [
    "state",
    "replayReceipt",
    "directory",
    "journal",
    "lock",
    "adapter",
    "provisionGates",
    "commitGates",
    "observations",
  ], "provenance completion registration input");
  const normalized = normalizeCompletedPhalaExecutorState(parsed.state);
  if (canonicalCompact(normalized) !== canonicalCompact(parsed.state)) {
    throw new Error("provenance completion state must already be exact and normalized");
  }
  const replay = assertDurablyPersistedProductionExecutionReplay({
    receipt: parsed.replayReceipt,
    directory: parsed.directory,
    state: parsed.state,
    journal: parsed.journal,
    lock: parsed.lock,
    adapter: parsed.adapter,
    provisionGates: parsed.provisionGates,
    commitGates: parsed.commitGates,
    observations: parsed.observations,
  });
  const stateDigest = phalaExecutorStateDigest(normalized);
  if (replay.executor_state_sha256 !== stateDigest
    || replay.batch_id !== normalized.batch_id
    || replay.bootstrap_authorization_id
      !== normalized.bootstrap_authorization_id
    || replay.release_sha !== normalized.release_sha
    || replay.target_authority_sha256 !== normalized.target_authority_sha256) {
    throw new Error("durable production replay does not identify the exact executor state");
  }
  PROVENANCE_VERIFIED_COMPLETED_STATES.set(parsed.state, stateDigest);
  return parsed.state;
}

/**
 * Re-establish the same completed-state provenance brand after a process
 * restart, but only through the module-private completed-launch continuation
 * capability. This path never recreates a mutation gate or renews historical
 * launch authority: the capability has already bound immutable L, the exact
 * terminal recovery journal/transcript, historical signed A at the recorded
 * mutation seconds, and a separately labelled current read-only continuity
 * receipt.
 */
export async function registerContinuityVerifiedCompletedPhalaExecutorState(
  options = {},
) {
  const parsed = exactRecord(options, [
    "continuationCapability",
  ], "completed-launch continuation provenance registration input");

  // Claim first. Any validation failure below permanently burns this
  // same-process capability, which is the intended fail-closed replay rule.
  const {
    claimCompletedPhalaSevenCvmLaunchContinuationForProvenance,
  } = await import("./phala-completed-launch-continuation.mjs");
  const dependencies =
    claimCompletedPhalaSevenCvmLaunchContinuationForProvenance(
      parsed.continuationCapability,
    );
  const state = dependencies.executor_final_state;
  const normalized = normalizeCompletedPhalaExecutorState(state);
  if (canonicalCompact(normalized) !== canonicalCompact(state)) {
    throw new Error(
      "continuation executor state must already be exact and normalized",
    );
  }
  const {
    normalizePhalaCompletedLaunchContinuityReceipt,
    phalaCompletedLaunchContinuityReceiptSha256,
  } = await import("./phala-completed-launch-continuation-core.mjs");
  const {
    phalaNonLiveBootstrapAuthorizationReceiptSha256,
  } = await import("./phala-nonlive-bootstrap-authorization-core.mjs");

  const receipt = normalizePhalaCompletedLaunchContinuityReceipt(
    dependencies.current_continuity_receipt,
  );
  const receiptSha256 = phalaCompletedLaunchContinuityReceiptSha256(receipt);
  const stateDigest = phalaExecutorStateDigest(normalized);
  const journal = dependencies.completed_recovery_journal;
  const launch = dependencies.persisted_launch_completion_receipt;
  const signedA = dependencies.signed_a_receipt;
  const target = dependencies.production_target_authority_evidence;
  const historicalEvidence = dependencies.historical_evidence_reconstruction;
  assertCanonicalPlainDataGraph(journal, {
    label: "continuation completed recovery journal",
  });
  assertCanonicalPlainDataGraph(launch, {
    label: "continuation immutable launch completion receipt",
  });
  if (!isRecord(journal)
    || journal.schema !== "dnai.phala-production-recovery-journal.v2"
    || journal.truth_status
      !== "private_recovery_metadata_no_secrets_ciphertext_or_phala_atomicity_claim"
    || journal.state_sha256 !== stateDigest
    || journal.batch_id !== normalized.batch_id
    || canonicalCompact(journal.state) !== canonicalCompact(normalized)
    || journal.seven_commit_batch_is_atomic !== false
    || journal.automatic_retry_authorized !== false
    || journal.automatic_cleanup_authorized !== false
    || !isRecord(launch)
    || launch.schema
      !== "dnai.phala-seven-cvm-launch-completion-receipt.v4"
    || launch.status
      !== "all_seven_committed_private_production_posture_and_machine_verifier_evidence_bound"
    || launch.all_seven_committed !== true
    || launch.all_seven_production_posture_validated !== true
    || launch.all_seven_machine_verified !== true
    || launch.live_traffic_authorized !== false
    || launch.late_secret_activation_authorized !== false
    || launch.compute_workload_recipient_activation_authorized !== false
    || launch.executor_final_state_sha256 !== stateDigest
    || launch.batch_id !== normalized.batch_id
    || launch.release_sha !== normalized.release_sha
    || launch.bootstrap_authorization_id
      !== normalized.bootstrap_authorization_id
    || launch.cvm_launch_intent_sha256 !== normalized.launch_intent_sha256
    || launch.production_target_authority_sha256
      !== normalized.target_authority_sha256
    || launch.phala_recovery_directory_identity_anchor_sha256
      !== normalized.phala_recovery_directory_identity_anchor_sha256
    || receipt.executor_final_state_sha256 !== stateDigest
    || receipt.release_sha !== normalized.release_sha
    || receipt.batch_id !== normalized.batch_id
    || receipt.production_target_authority_sha256
      !== normalized.target_authority_sha256
    || receipt.launch_completion_receipt_sha256
      !== dependencies.persisted_launch_completion_receipt_sha256
    || receipt.launch_completion_raw_file_sha256
      !== dependencies.persisted_launch_completion_raw_file_sha256
    || receipt.nonlive_bootstrap_authorization_receipt_sha256
      !== phalaNonLiveBootstrapAuthorizationReceiptSha256(signedA)
    || receipt.nonlive_bootstrap_authorization_receipt_sha256
      !== normalized.bootstrap_authorization_receipt_sha256
    || receipt.seven_cvm_verified_evidence_set_sha256
      !== historicalEvidence?.seven_cvm_verified_evidence_set_sha256
    || receipt.historical_transcript_file_set_sha256
      !== historicalEvidence?.historical_transcript_file_set_sha256
    || receiptSha256 !== dependencies.current_continuity_receipt_sha256
    || target?.productionTargetAuthoritySha256
      !== normalized.target_authority_sha256
    || dependencies.historical_launch_refreshed !== false
    || dependencies.historical_evidence_refreshed !== false
    || dependencies.live_traffic_authorized !== false) {
    throw new Error(
      "completed-launch continuation does not identify one exact historical executor lineage",
    );
  }
  PROVENANCE_VERIFIED_COMPLETED_STATES.set(state, stateDigest);
  return state;
}

export function buildExactCommitMetadata({
  appId,
  composeHash,
  kmsId,
  environmentKeys,
} = {}) {
  return {
    app_id: exactAppId(appId, "commit app id"),
    compose_hash: exactBareDigest(composeHash, "commit compose hash"),
    kms_id: exactIdentifier(kmsId, "commit KMS id"),
    env_keys: sortedUniqueEnvironmentKeys(environmentKeys, "commit env_keys"),
  };
}
