import {
  CVM_LAUNCH_DOMAINS,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";

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

export function assertProductionCvmPosture(cvmInfo, expected = {}) {
  if (!isRecord(cvmInfo)
    || cvmInfo.app_id?.replace(/^0x/, "") !== exactAppId(expected.appId, "expected app id")
    || cvmInfo.compose_hash !== exactBareDigest(expected.composeHash, "expected compose hash")
    || cvmInfo.kms_info?.id !== expected.kmsId
    || cvmInfo.kms_type !== "phala"
    || cvmInfo.os?.os_image_hash !== PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash
    || cvmInfo.os?.is_dev !== false
    || cvmInfo.resource?.instance_type !== expected.instanceType
    || cvmInfo.resource?.disk_in_gb !== expected.diskSize
    || cvmInfo.listed !== false
    || cvmInfo.public_logs !== false
    || cvmInfo.public_sysinfo !== false
    || cvmInfo.public_tcbinfo !== false) {
    throw new Error("committed CVM does not match the complete private production posture");
  }
  return cvmInfo;
}
