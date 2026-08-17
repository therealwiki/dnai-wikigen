import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_EXECUTION_ORDER,
  assertProductionCvmPosture,
  assertSecretFreeExecutorStructure,
} from "./phala-production-posture-core.mjs";

export const PHALA_PRODUCTION_CVM_POSTURE_RECEIPT_SCHEMA =
  "dnai.phala-production-cvm-posture-verification-receipt.v1";
export const PHALA_PRODUCTION_CVM_POSTURE_RECEIPT_DOMAIN =
  "dnai-wikigen/phala-production-cvm-posture-verification-receipt/v1\0";
export const PHALA_CVM_INFO_OBSERVATION_DOMAIN =
  "dnai-wikigen/phala-cvm-info-observation/v1\0";

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const INSTANCE = /^[a-z][a-z0-9.-]{1,63}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const VERIFIED_POSTURE_RECEIPTS = new WeakSet();

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonical(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function sha256Domain(domain, bytes) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(bytes)
    .digest("hex")}`;
}

function digest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new Error(`${label} must be a canonical identifier`);
  }
  return value;
}

function timestamp(value, label) {
  const parsedMs = typeof value === "string" && ISO_SECOND.test(value)
    ? Date.parse(value)
    : Number.NaN;
  if (!Number.isFinite(parsedMs)
    || new Date(parsedMs).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  return value;
}

function normalizeExpected(value) {
  const expected = exactRecord(value, [
    "domain",
    "app_id",
    "cvm_id",
    "compose_hash",
    "kms_id",
    "instance_type",
    "disk_size",
  ], "production CVM posture expected authority");
  if (!PHALA_EXECUTION_ORDER.includes(expected.domain)
    || typeof expected.app_id !== "string" || !APP_ID.test(expected.app_id)
    || typeof expected.compose_hash !== "string"
    || !BARE_SHA256.test(expected.compose_hash)
    || typeof expected.instance_type !== "string"
    || !INSTANCE.test(expected.instance_type)
    || !Number.isSafeInteger(expected.disk_size)
    || expected.disk_size < 20 || expected.disk_size > 16_384) {
    throw new Error("production CVM posture expected authority is invalid");
  }
  return {
    domain: expected.domain,
    app_id: expected.app_id,
    cvm_id: identifier(expected.cvm_id, "expected CVM id"),
    compose_hash: expected.compose_hash,
    kms_id: identifier(expected.kms_id, "expected KMS id"),
    instance_type: expected.instance_type,
    disk_size: expected.disk_size,
  };
}

export function normalizeProductionCvmPostureVerificationReceipt(value, {
  expectedAuthority,
} = {}) {
  assertCanonicalPlainDataGraph(value, { label: "production CVM posture receipt" });
  const expected = normalizeExpected(expectedAuthority);
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    "domain",
    "app_id",
    "cvm_id",
    "compose_hash",
    "kms_id",
    "instance_type",
    "disk_size",
    "os_image_hash",
    "kms_type",
    "listed",
    "public_logs",
    "public_sysinfo",
    "public_tcbinfo",
    "cvm_info_observation_sha256",
    "observed_at",
    "raw_secret_egress",
  ], "production CVM posture receipt");
  if (parsed.schema !== PHALA_PRODUCTION_CVM_POSTURE_RECEIPT_SCHEMA
    || parsed.status !== "private_production_posture_verified"
    || parsed.truth_status
      !== "fresh_getCvmInfo_observation_matches_exact_committed_app_compose_kms_os_resource_and_privacy_posture"
    || parsed.domain !== expected.domain
    || parsed.app_id !== expected.app_id
    || parsed.cvm_id !== expected.cvm_id
    || parsed.compose_hash !== expected.compose_hash
    || parsed.kms_id !== expected.kms_id
    || parsed.instance_type !== expected.instance_type
    || parsed.disk_size !== expected.disk_size
    || parsed.os_image_hash !== PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash
    || parsed.kms_type !== "phala"
    || parsed.listed !== false
    || parsed.public_logs !== false
    || parsed.public_sysinfo !== false
    || parsed.public_tcbinfo !== false
    || parsed.raw_secret_egress !== false) {
    throw new Error("production CVM posture receipt does not match exact authority");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_PRODUCTION_CVM_POSTURE_RECEIPT_SCHEMA,
    status: "private_production_posture_verified",
    truth_status:
      "fresh_getCvmInfo_observation_matches_exact_committed_app_compose_kms_os_resource_and_privacy_posture",
    domain: expected.domain,
    app_id: expected.app_id,
    cvm_id: expected.cvm_id,
    compose_hash: expected.compose_hash,
    kms_id: expected.kms_id,
    instance_type: expected.instance_type,
    disk_size: expected.disk_size,
    os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
    kms_type: "phala",
    listed: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
    cvm_info_observation_sha256: digest(
      parsed.cvm_info_observation_sha256,
      "CVM info observation digest",
    ),
    observed_at: timestamp(parsed.observed_at, "CVM posture observed_at"),
    raw_secret_egress: false,
  }, { label: "normalized production CVM posture receipt" });
}

export function verifyProductionCvmPostureObservation(options = {}) {
  const {
    domain,
    cvmId,
    cvmInfo,
    expected,
  } = exactRecord(options, [
    "domain",
    "cvmId",
    "cvmInfo",
    "expected",
  ], "production CVM posture verification input");
  assertCanonicalPlainDataGraph(cvmInfo, { label: `${domain} raw getCvmInfo observation` });
  assertSecretFreeExecutorStructure(cvmInfo, `${domain} raw getCvmInfo observation`);
  const authority = normalizeExpected({
    domain,
    app_id: expected?.appId,
    cvm_id: cvmId,
    compose_hash: expected?.composeHash,
    kms_id: expected?.kmsId,
    instance_type: expected?.instanceType,
    disk_size: expected?.diskSize,
  });
  if (cvmInfo.id !== authority.cvm_id) {
    throw new Error("getCvmInfo response does not identify the requested CVM ID");
  }
  assertProductionCvmPosture(cvmInfo, {
    appId: authority.app_id,
    composeHash: authority.compose_hash,
    kmsId: authority.kms_id,
    instanceType: authority.instance_type,
    diskSize: authority.disk_size,
  });
  const receipt = normalizeProductionCvmPostureVerificationReceipt({
    schema: PHALA_PRODUCTION_CVM_POSTURE_RECEIPT_SCHEMA,
    status: "private_production_posture_verified",
    truth_status:
      "fresh_getCvmInfo_observation_matches_exact_committed_app_compose_kms_os_resource_and_privacy_posture",
    domain: authority.domain,
    app_id: authority.app_id,
    cvm_id: authority.cvm_id,
    compose_hash: authority.compose_hash,
    kms_id: authority.kms_id,
    instance_type: authority.instance_type,
    disk_size: authority.disk_size,
    os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
    kms_type: "phala",
    listed: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
    cvm_info_observation_sha256: sha256Domain(
      PHALA_CVM_INFO_OBSERVATION_DOMAIN,
      canonical(cvmInfo),
    ),
    // Production posture time is taken at the verification boundary. Accepting
    // a caller timestamp would let captured getCvmInfo bytes be backdated into
    // an authorization window they were not observed in.
    observed_at: new Date(Math.floor(Date.now() / 1_000) * 1_000)
      .toISOString().replace(".000Z", "Z"),
    raw_secret_egress: false,
  }, { expectedAuthority: authority });
  VERIFIED_POSTURE_RECEIPTS.add(receipt);
  return receipt;
}

export function assertVerifiedProductionCvmPostureReceipt(value) {
  if (!value || !VERIFIED_POSTURE_RECEIPTS.has(value)) {
    throw new Error("production CVM posture receipt was not reconstructed from getCvmInfo");
  }
  return value;
}

export function canonicalProductionCvmPostureVerificationReceiptText(value, options = {}) {
  const normalized = VERIFIED_POSTURE_RECEIPTS.has(value)
    ? value
    : normalizeProductionCvmPostureVerificationReceipt(value, options);
  return canonical(normalized);
}

export function productionCvmPostureVerificationReceiptSha256(value, options = {}) {
  return sha256Domain(
    PHALA_PRODUCTION_CVM_POSTURE_RECEIPT_DOMAIN,
    canonicalProductionCvmPostureVerificationReceiptText(value, options),
  );
}
