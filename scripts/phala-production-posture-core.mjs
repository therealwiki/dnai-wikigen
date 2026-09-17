import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  PHALA_CVM_RESOURCE_TARGETS,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import { parseCanonicalPublicHttpsUrl } from "./canonical-public-https-url-core.mjs";
import { normalizePhalaContractKmsProjection } from "./phala-contract-kms-core.mjs";

export const PHALA_EXECUTION_ORDER = Object.freeze([
  ...CVM_LAUNCH_DOMAINS.filter((domain) => domain !== "main_runtime_cvm"),
  "main_runtime_cvm",
]);

const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const MAX_STATE_BYTES = 512 * 1024;
const FORBIDDEN_STATE_KEY = /(?:secret|password|private[_-]?key|bearer|credential|api[_-]?key|token|encrypted[_-]?env|ciphertext|plaintext|environment[_-]?values)/i;
const FORBIDDEN_STATE_VALUE = /(?:phak_[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  assertCanonicalPlainDataGraph(value, { label });
  if (!isRecord(value) || JSON.stringify(Object.keys(value).sort())
    !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the reviewed fields`);
  }
  return value;
}

export function normalizeProductionCvmEnvironmentPublicKey(value) {
  if (typeof value !== "string" || !/^(?:0x)?(?!0{64}$)[0-9a-f]{64}$/.test(value)) {
    throw new Error("production environment public key must be exactly 32 nonzero bytes");
  }
  return value.replace(/^0x/, "");
}

// Shape validation preserves historical prepare facts; it does not establish
// that any preparation occurred. Reopening a session also requires the exact
// projection check below and a verified persisted posture receipt.
export function normalizeProductionCvmPreparedBinding(value) {
  const binding = exactRecord(value, [
    "kms_contract_id", "kms_id", "kms_url", "node_id", "teepod_id", "device_id", "gateway_app_id",
  ], "production CVM prepared binding");
  if (typeof binding.kms_contract_id !== "string" || !/^kc_[A-Za-z0-9]{1,128}$/.test(binding.kms_contract_id)
    || typeof binding.kms_id !== "string" || !/^kms_[A-Za-z0-9]{1,128}$/.test(binding.kms_id)
    || !Number.isSafeInteger(binding.node_id) || binding.node_id < 1
    || !Number.isSafeInteger(binding.teepod_id) || binding.teepod_id < 1
    || typeof binding.device_id !== "string" || !BARE_SHA256.test(binding.device_id)
    || (binding.gateway_app_id !== null && (typeof binding.gateway_app_id !== "string"
      || !/^0x(?!0{40}$)[0-9a-f]{40}$/.test(binding.gateway_app_id)))) {
    throw new Error("production CVM prepared binding identity is invalid");
  }
  const endpoint = parseCanonicalPublicHttpsUrl(binding.kms_url, {
    label: "prepared KMS RPC URL", allowPort: true,
  }).href;
  if (endpoint !== binding.kms_url) throw new Error("prepared KMS RPC URL must be canonical");
  return deepFreezeCanonicalPlainDataGraph({ ...binding }, { label: "prepared binding" });
}

export function assertProductionCvmPreparedBinding(options) {
  const { preparedBinding, kmsProjection, domain } = exactRecord(options,
    ["preparedBinding", "kmsProjection", "domain"], "prepared binding projection check");
  if (!CVM_LAUNCH_DOMAINS.includes(domain)) throw new Error("prepared binding domain is invalid");
  const binding = normalizeProductionCvmPreparedBinding(preparedBinding);
  const projection = normalizePhalaContractKmsProjection(kmsProjection, {
    osImage: PHALA_OS_IMAGE_CATALOG_ENTRY,
    resourceTargets: Object.fromEntries(CVM_LAUNCH_DOMAINS.map((targetDomain) => [targetDomain, {
      ...PHALA_CVM_RESOURCE_TARGETS[targetDomain],
      gateway_required: CVM_LAUNCH_DESCRIPTOR_POLICY[targetDomain].app_compose_candidate.gateway_enabled,
    }])),
  });
  const replica = projection.replicas.find((entry) => entry.id === binding.kms_id);
  const placements = projection.eligible_placements.filter((entry) => (
    entry.kms_contract_id === binding.kms_contract_id && entry.kms_id === binding.kms_id
    && entry.node_id === binding.node_id && entry.teepod_id === binding.teepod_id
    && entry.target_domains.includes(domain)
    && entry.device_ids.some((device) => device.enabled === true && device.device_id === binding.device_id)
  ));
  const gatewayRequired = CVM_LAUNCH_DESCRIPTOR_POLICY[domain].app_compose_candidate.gateway_enabled;
  if (binding.kms_contract_id !== projection.contract.id || !replica
    || replica.url !== binding.kms_url || placements.length !== 1
    || binding.gateway_app_id !== (gatewayRequired ? placements[0].gateway_app_id : null)) {
    throw new Error("durable prepared binding differs from the exact reviewed contract/replica/placement graph");
  }
  return binding;
}

function exactAppId(value, label) {
  if (typeof value !== "string") throw new Error(`${label} is invalid`);
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  if (!APP_ID.test(normalized)) throw new Error(`${label} must be exactly 20 nonzero bytes`);
  return normalized;
}

function exactBareDigest(value, label) {
  if (typeof value !== "string" || !BARE_SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero bare SHA-256 digest`);
  }
  return value;
}

export function assertSecretFreeExecutorStructure(value, label = "executor structure") {
  function walk(entry) {
    if (typeof entry === "string") {
      if (FORBIDDEN_STATE_VALUE.test(entry)) {
        throw new Error(`${label} contains a forbidden secret-shaped value`);
      }
      return;
    }
    if (Array.isArray(entry)) {
      entry.forEach(walk);
      return;
    }
    if (!isRecord(entry)) return;
    for (const [key, nested] of Object.entries(entry)) {
      // This SDK field is a public X25519 key, never an encrypted environment.
      // The sole exception is bounded to its exact spelling and encoding.
      if (key === "encrypted_env_pubkey") {
        normalizeProductionCvmEnvironmentPublicKey(nested);
        continue;
      }
      if (FORBIDDEN_STATE_KEY.test(key)) {
        throw new Error(`${label} contains a forbidden secret-bearing field`);
      }
      walk(nested);
    }
  }
  walk(value);
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_STATE_BYTES) {
    throw new Error(`${label} exceeds the bounded serialized size`);
  }
  return true;
}

/** Project only actual public SDK readback fields; never infer IDs or defaults. */
export function projectProductionCvmPostureReadback(raw, cvmId) {
  assertCanonicalPlainDataGraph(raw, { label: "SDK CVM posture source" });
  if (!isRecord(raw) || typeof raw.id !== "string" || raw.id.length === 0
    || typeof cvmId !== "string" || raw.id !== cvmId) {
    throw new Error("CVM posture source must explicitly identify the requested CVM");
  }
  const pick = (value, fields, label) => {
    if (!isRecord(value)) throw new Error(`${label} must be an actual SDK object`);
    return Object.fromEntries(fields.filter((field) => Object.hasOwn(value, field))
      .map((field) => [field, structuredClone(value[field])]));
  };
  const projection = {
    id: String(raw.id),
    ...pick(raw, ["app_id", "compose_hash", "kms_type", "listed", "public_logs", "public_sysinfo", "public_tcbinfo"],
      "CVM posture source"),
    kms_info: pick(raw.kms_info, ["chain_id", "dstack_kms_address", "dstack_app_address", "deployer_address",
      "rpc_endpoint", "encrypted_env_pubkey"], "CVM KMS readback"),
    node_info: pick(raw.node_info, ["id"], "CVM node readback"),
    os: pick(raw.os, ["os_image_hash", "is_dev"], "CVM OS readback"),
    resource: pick(raw.resource, ["instance_type", "disk_in_gb"], "CVM resource readback"),
  };
  if (Object.hasOwn(raw.node_info, "device_ids")) {
    if (!Array.isArray(raw.node_info.device_ids)) throw new Error("CVM device matrix must be an actual SDK array");
    projection.node_info.device_ids = raw.node_info.device_ids.map((device) => pick(device,
      ["device_id", "algorithm_version", "enabled"], "CVM device readback"));
  }
  assertSecretFreeExecutorStructure(projection, "public CVM posture readback");
  return deepFreezeCanonicalPlainDataGraph(projection, { label: "public CVM posture readback" });
}

export function assertProductionCvmPosture(cvmInfo, expected = {}) {
  assertCanonicalPlainDataGraph(cvmInfo, { label: "production CVM readback" });
  exactRecord(expected, [
    "domain", "appId", "composeHash", "instanceType", "diskSize", "kmsProjection",
    "preparedBinding", "environmentPublicKey",
  ], "production CVM posture expectation");
  const binding = assertProductionCvmPreparedBinding({
    preparedBinding: expected.preparedBinding, kmsProjection: expected.kmsProjection, domain: expected.domain,
  });
  const environmentKey = normalizeProductionCvmEnvironmentPublicKey(expected.environmentPublicKey);
  const kmsInfo = cvmInfo?.kms_info;
  const devices = cvmInfo?.node_info?.device_ids;
  const reviewedPlacement = expected.kmsProjection.eligible_placements.find((placement) => (
    placement.node_id === binding.node_id && placement.teepod_id === binding.teepod_id
    && placement.kms_id === binding.kms_id && placement.target_domains.includes(expected.domain)
  ));
  const reviewedDevice = reviewedPlacement.device_ids.find((device) => device.device_id === binding.device_id);
  const rpc = typeof kmsInfo?.rpc_endpoint === "string"
    ? parseCanonicalPublicHttpsUrl(kmsInfo.rpc_endpoint, {
      label: "readback KMS RPC endpoint", allowPort: true,
    }).href : null;
  const resourceTarget = PHALA_CVM_RESOURCE_TARGETS[expected.domain];
  if (!isRecord(cvmInfo)
    || cvmInfo.app_id?.replace(/^0x/, "") !== exactAppId(expected.appId, "expected app id")
    || cvmInfo.compose_hash !== exactBareDigest(expected.composeHash, "expected compose hash")
    || !isRecord(kmsInfo) || rpc !== binding.kms_url
    || (kmsInfo.chain_id !== null && kmsInfo.chain_id !== undefined)
    || ["dstack_kms_address", "dstack_app_address", "deployer_address"].some((key) => (
      kmsInfo[key] !== undefined && kmsInfo[key] !== null && kmsInfo[key] !== ""
    ))
    || normalizeProductionCvmEnvironmentPublicKey(kmsInfo.encrypted_env_pubkey) !== environmentKey
    || cvmInfo.node_info?.id !== binding.node_id
    || !Array.isArray(devices) || devices.length < 1 || devices.length > 16
    || new Set(devices.map((device) => device.device_id)).size !== devices.length
    || !devices.some((device) => device.device_id === binding.device_id && device.enabled === true
      && device.algorithm_version === reviewedDevice.algorithm_version)
    || cvmInfo.kms_type !== "phala"
    || cvmInfo.os?.os_image_hash !== PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash
    || cvmInfo.os?.is_dev !== false
    || cvmInfo.resource?.instance_type !== expected.instanceType
    || cvmInfo.resource?.disk_in_gb !== expected.diskSize
    || expected.instanceType !== resourceTarget.instance_type || expected.diskSize !== resourceTarget.disk_size
    || cvmInfo.listed !== false
    || cvmInfo.public_logs !== false
    || cvmInfo.public_sysinfo !== false
    || cvmInfo.public_tcbinfo !== false) {
    throw new Error("committed CVM does not match the complete private production posture");
  }
  return cvmInfo;
}
