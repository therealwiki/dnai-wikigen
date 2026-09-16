import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SCHEMA =
  "dnai.phala-sdk-runtime-capsule-authority.v1";
export const PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SHA256 =
  "sha256:c6a9e84e62331ed929cae422166980e50c390dcb553c82436b7043c1f3a4ba7c";
export const PHALA_SDK_RUNTIME_CAPSULE_SHA256 =
  "sha256:55249c4d189dea6aad95cdefd3e0310f4dfadbcc1f5d7e11ced1ddda5200d457";
export const PHALA_SDK_RUNTIME_CAPSULE_LEGAL_NOTICE_SHA256 =
  "sha256:e0db15fc6e8e94df1c13d0cc483b57d6ad695c1506797da0d0bc4be4f60d0210";
export const PHALA_SDK_ACTION_REQUEST_POLICY_SHA256 =
  "sha256:c2fe6c0baf65972bb1b6326a535123cb187bc36a0680b5183d1568a89879c495";
export const PHALA_SDK_UPSTREAM_REGISTRY_EVIDENCE_SHA256 =
  "sha256:847b1831fd971204e45bb2da03b00e3761d78d2495f9ff8ae83365c94a7a10c2";
export const PHALA_REVIEWED_NODE_RUNTIME = Object.freeze({
  version: "v24.9.0",
  executable_realpath: "/opt/homebrew/Cellar/node/24.9.0/bin/node",
  executable_sha256:
    "sha256:3e7673f6552cffd3f9eaa3bcb910198a4d0786e99bb861d24eb81cc3fce563e7",
  executable_byte_length: 64_221_968,
  ownership_status:
    "operator_owned_mode_0555_operational_trust_boundary_not_root_owned",
});
export const PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY = Object.freeze({
  node_runtime_version: PHALA_REVIEWED_NODE_RUNTIME.version,
  node_runtime_executable_realpath:
    PHALA_REVIEWED_NODE_RUNTIME.executable_realpath,
  node_runtime_executable_sha256:
    PHALA_REVIEWED_NODE_RUNTIME.executable_sha256,
  node_runtime_executable_byte_length:
    PHALA_REVIEWED_NODE_RUNTIME.executable_byte_length,
  node_runtime_ownership_status:
    PHALA_REVIEWED_NODE_RUNTIME.ownership_status,
  sdk_runtime_capsule_schema: PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SCHEMA,
  sdk_runtime_capsule_authority_sha256:
    PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SHA256,
  sdk_runtime_capsule_sha256: PHALA_SDK_RUNTIME_CAPSULE_SHA256,
  sdk_action_request_policy_sha256: PHALA_SDK_ACTION_REQUEST_POLICY_SHA256,
  sdk_upstream_registry_evidence_sha256:
    PHALA_SDK_UPSTREAM_REGISTRY_EVIDENCE_SHA256,
  phala_cloud_version: "0.2.10",
  phala_cloud_source_package_manifest_sha256:
    "sha256:0ac15a2c4f80b3ba8ff6c7f45cdfbcdff22075967458ebd4af988be85ef804c7",
  phala_cloud_source_module_sha256:
    "sha256:ad67b0bda91dd37566dac18030aac8c267e5b88b931f12e37614e537b465729f",
  phala_cloud_module_sha256:
    "sha256:ad67b0bda91dd37566dac18030aac8c267e5b88b931f12e37614e537b465729f",
  phala_cloud_source_tarball_sha256:
    "sha256:5e7b91e84bc0aa4a3273c205c96103a7cdbdcb577ce0e0e740e54789e8e4f1b7",
  phala_cloud_npm_dist_integrity_sha512:
    "sha512-eQXJxbBlJ8xA4e+MmB3AZd9jgdbO3tFh+qu7KL6CS5Ta64LNKlrV3vdke3oUvB22xbc/qqKQ6dIkJx5pTdY7gA==",
  dstack_sdk_version: "0.5.8",
  dstack_source_package_manifest_sha256:
    "sha256:3f7ef87b62b041be1e997ce18f87652694312cfc52c80efeb4ecdbff0f3a17c9",
  dstack_source_compose_hash_module_sha256:
    "sha256:491f6c895886e14304311d96daab3546932edf322dfc471f4db05ba39ab1f9e3",
  dstack_source_verify_module_sha256:
    "sha256:da23da4169d0ff2e7281a25be7fe151c829a17899ad53f8cc7b11076775eeed2",
  dstack_source_encryption_module_sha256:
    "sha256:3cb0b94ac05be529ab4f1719e62194355c4543d08fd7f77174b1c89be22f5837",
  dstack_encryption_module_sha256:
    "sha256:3cb0b94ac05be529ab4f1719e62194355c4543d08fd7f77174b1c89be22f5837",
  dstack_source_tarball_sha256:
    "sha256:a78a0ffcc429c22c939b9c92b05406881c56220927a3462cc70de9d6c1d5d15c",
  dstack_npm_dist_integrity_sha512:
    "sha512-VANlyo0Jj6pxmJl3zksHJ4/5y3VflApVmgsfcfmokk3KYKRBkW5oMkexBTR6lZaGVPOqJ48QGOLP/7CF3IEvFg==",
});
export const PHALA_REVIEWED_CAPSULE_EXPORTS = Object.freeze([
  "commitCvmProvision",
  "encryptEnvVars",
  "getAppEnvEncryptPubKey",
  "getComposeHash",
  "getCurrentUser",
  "getCvmAttestation",
  "getCvmCreateResources",
  "getCvmInfo",
  "getCvmList",
  "getKmsInfo",
  "getKmsList",
  "getOsImages",
  "nextAppIds",
  "provisionCvm",
  "restartCvm",
  "updateCvmEnvs",
  "verifyEnvEncryptPublicKey",
  "verifyEnvEncryptPublicKeyLegacy",
]);

const AUTHORITY_PATH = fileURLToPath(new URL(
  "../deployments/phala-sdk-runtime-capsule-authority.json",
  import.meta.url,
));
const REGISTRY_EVIDENCE_PATH = fileURLToPath(new URL(
  "../deployments/phala-sdk-upstream-registry-evidence.json",
  import.meta.url,
));
const CAPSULE_PATH = fileURLToPath(new URL(
  "./vendor/phala-sdk-runtime-capsule-0.2.10-0.5.8.mjs",
  import.meta.url,
));
const LEGAL_NOTICE_PATH = fileURLToPath(new URL(
  "./vendor/phala-sdk-runtime-capsule-0.2.10-0.5.8.mjs.LEGAL.txt",
  import.meta.url,
));
const CLOUD_TARBALL_PATH = fileURLToPath(new URL(
  "./vendor/npm/phala-cloud-0.2.10.tgz",
  import.meta.url,
));
const DSTACK_TARBALL_PATH = fileURLToPath(new URL(
  "./vendor/npm/phala-dstack-sdk-0.5.8.tgz",
  import.meta.url,
));
const MAX_AUTHORITY_BYTES = 16 * 1024;
const MAX_REGISTRY_EVIDENCE_BYTES = 16 * 1024;
const MAX_CAPSULE_BYTES = 1024 * 1024;
const MAX_LEGAL_NOTICE_BYTES = 32 * 1024;
const MAX_TARBALL_BYTES = 512 * 1024;
const MAX_NODE_BYTES = 80 * 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW;
const CAPSULE_STATE = new WeakMap();
const CAPSULE_IDENTITY = new WeakSet();
const EXPECTED_AUTHORITY_TRUTH =
  "reviewed_static_data_url_sdk_runtime_capsule_exact_bytes_and_source_tarball_integrity_not_node_binary_provenance_network_or_launch_authority";
const EXPECTED_REGISTRY_EVIDENCE_TRUTH =
  "fresh_public_npm_registry_https_bytes_signature_and_attestation_verification_not_future_revocation_or_reproducible_bundle_build_authority";
const EXPECTED_BUILTIN_IMPORTS = Object.freeze(["crypto", "node:crypto"]);

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonicalJsonText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function readStableReviewedFile(filePath, label, maximum) {
  if (NOFOLLOW === undefined || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath
    || fs.realpathSync.native(filePath) !== filePath) {
    throw new Error(`${label} path is not canonical or no-follow capable`);
  }
  const beforePath = fs.lstatSync(filePath, { bigint: true });
  if (!beforePath.isFile() || beforePath.isSymbolicLink()
    || beforePath.nlink !== 1n || beforePath.uid !== BigInt(process.getuid())
    || (beforePath.mode & 0o022n) !== 0n
    || beforePath.size < 2n || beforePath.size > BigInt(maximum)) {
    throw new Error(`${label} is not an owned bounded single-link non-writable regular file`);
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd, { bigint: true });
    const finalPath = fs.lstatSync(filePath, { bigint: true });
    const fields = [
      "dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs",
    ];
    if (fields.some((field) => beforePath[field] !== before[field]
        || before[field] !== after[field] || after[field] !== finalPath[field])
      || bytes.length !== Number(before.size)) {
      throw new Error(`${label} pathname or bytes changed during its stable read`);
    }
    return Object.freeze({
      bytes,
      sha256: sha256(bytes),
      mode: after.mode,
      uid: after.uid,
    });
  } finally {
    fs.closeSync(fd);
  }
}

function exactAuthority(authorityBytes) {
  if (!Buffer.isBuffer(authorityBytes)
    || sha256(authorityBytes) !== PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SHA256) {
    throw new Error("Phala SDK runtime capsule authority digest is not the reviewed static pin");
  }
  let authority;
  try {
    authority = JSON.parse(authorityBytes.toString("utf8"));
  } catch {
    throw new Error("Phala SDK runtime capsule authority is not JSON");
  }
  if (canonicalJsonText(authority) !== authorityBytes.toString("utf8")
    || authority?.schema !== PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SCHEMA
    || authority?.truth_status !== EXPECTED_AUTHORITY_TRUTH
    || authority?.capsule?.path
      !== "scripts/vendor/phala-sdk-runtime-capsule-0.2.10-0.5.8.mjs"
    || authority?.capsule?.sha256 !== PHALA_SDK_RUNTIME_CAPSULE_SHA256
    || authority?.capsule?.byte_length !== 454_408
    || authority?.capsule?.format !== "single_esm_data_url_module"
    || authority?.capsule?.dynamic_imports_allowed !== false
    || JSON.stringify(authority?.capsule?.builtin_imports)
      !== JSON.stringify(EXPECTED_BUILTIN_IMPORTS)
    || JSON.stringify(authority?.capsule?.exports)
      !== JSON.stringify(PHALA_REVIEWED_CAPSULE_EXPORTS)
    || authority?.legal_notice?.path
      !== "scripts/vendor/phala-sdk-runtime-capsule-0.2.10-0.5.8.mjs.LEGAL.txt"
    || authority?.legal_notice?.sha256
      !== PHALA_SDK_RUNTIME_CAPSULE_LEGAL_NOTICE_SHA256
    || authority?.legal_notice?.byte_length !== 15_414
    || JSON.stringify(authority?.legal_notice?.components) !== JSON.stringify([
      "@noble/curves@1.9.7",
      "@noble/hashes@1.8.0",
      "@phala/cloud@0.2.10",
      "@phala/dstack-sdk@0.5.8",
      "viem@2.55.4",
      "zod@3.25.76",
    ])
    || authority?.request_policy?.action_count !== 14
    || authority?.request_policy?.sha256 !== PHALA_SDK_ACTION_REQUEST_POLICY_SHA256
    || authority?.registry_evidence?.path
      !== "deployments/phala-sdk-upstream-registry-evidence.json"
    || authority?.registry_evidence?.sha256
      !== PHALA_SDK_UPSTREAM_REGISTRY_EVIDENCE_SHA256
    || authority?.registry_evidence?.truth_status !== EXPECTED_REGISTRY_EVIDENCE_TRUTH
    || JSON.stringify(sorted(authority?.node_runtime))
      !== JSON.stringify(sorted(PHALA_REVIEWED_NODE_RUNTIME))) {
    throw new Error("Phala SDK runtime capsule authority fields differ from the reviewed pin");
  }
  return authority;
}

function exactRegistryEvidence(registryEvidenceBytes, authority) {
  if (!Buffer.isBuffer(registryEvidenceBytes)
    || sha256(registryEvidenceBytes) !== PHALA_SDK_UPSTREAM_REGISTRY_EVIDENCE_SHA256) {
    throw new Error("Phala SDK upstream registry evidence differs from its reviewed pin");
  }
  let evidence;
  try {
    evidence = JSON.parse(registryEvidenceBytes.toString("utf8"));
  } catch {
    throw new Error("Phala SDK upstream registry evidence is not JSON");
  }
  if (canonicalJsonText(evidence) !== registryEvidenceBytes.toString("utf8")
    || evidence?.schema !== "dnai.phala-sdk-upstream-registry-evidence.v1"
    || evidence?.truth_status !== EXPECTED_REGISTRY_EVIDENCE_TRUTH
    || evidence?.registry?.origin !== "https://registry.npmjs.org"
    || evidence?.registry?.request_authentication !== "none_public_registry"
    || evidence?.verification?.ambient_registry_tokens_used !== false
    || evidence?.verification?.empty_home_and_private_npm_cache !== true
    || evidence?.verification?.tarballs_refetched_and_byte_hashed !== true
    || JSON.stringify(evidence?.verification?.external_network_hosts)
      !== JSON.stringify(["registry.npmjs.org"])
    || !Array.isArray(evidence?.packages) || evidence.packages.length !== 2) {
    throw new Error("Phala SDK upstream registry evidence claims are not exact");
  }
  const expectations = [
    ["@phala/cloud", authority.source_packages.phala_cloud],
    ["@phala/dstack-sdk", authority.source_packages.dstack_sdk],
  ];
  for (let index = 0; index < expectations.length; index += 1) {
    const [name, source] = expectations[index];
    const entry = evidence.packages[index];
    if (entry?.name !== name || entry?.version !== source.package_version
      || entry?.tarball_sha256 !== source.tarball_sha256
      || entry?.npm_dist_integrity_sha512 !== source.npm_dist_integrity_sha512
      || entry?.npm_dist_shasum_sha1 !== source.npm_dist_shasum
      || entry?.registry_signature?.keyid
        !== "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"
      || entry?.registry_signature?.verified !== true
      || entry?.attestation_count !== 2
      || entry?.attestations_verified !== true
      || JSON.stringify(entry?.predicate_types) !== JSON.stringify([
        "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
        "https://slsa.dev/provenance/v1",
      ])) {
      throw new Error("Phala SDK upstream registry package evidence is inconsistent");
    }
  }
  return evidence;
}

function exactSri(bytes, expected, label) {
  const observed = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  if (observed !== expected) {
    throw new Error(`${label} does not match its reviewed npm dist integrity`);
  }
}

export function assertReviewedCapsuleSourceCapabilityBoundary(capsuleBytes) {
  if (!Buffer.isBuffer(capsuleBytes) || capsuleBytes.length < 2
    || capsuleBytes.length > MAX_CAPSULE_BYTES) {
    throw new Error("Phala SDK runtime capsule source is not bounded bytes");
  }
  const source = capsuleBytes.toString("utf8");
  const importSpecifiers = [...source.matchAll(
    /^\s*import\s+(?:[^"']+?\s+from\s+)?["']([^"']+)["'];?\s*$/gmu,
  )].map((match) => match[1]).sort();
  if (JSON.stringify(importSpecifiers) !== JSON.stringify(EXPECTED_BUILTIN_IMPORTS)) {
    throw new Error("Phala SDK runtime capsule imports an unreviewed runtime module");
  }
  const forbidden = [
    /\b(?:fetch|XMLHttpRequest|WebSocket)\b/u,
    /\b(?:eval|Function)\b/u,
    /\bWebAssembly\b/u,
    /\bprocess\s*(?:\.|\[|\?\.)/u,
    /\bimport\s*\(/u,
    /\brequire\s*\(/u,
    /\b__require\s*\(/u,
    /\b(?:Deno|Bun)\s*(?:\.|\[)/u,
    /["'](?:node:)?(?:child_process|cluster|dgram|dns|fs|http|https|module|net|tls|vm|worker_threads)["']/u,
    /\.node(?:["'`]|\b)/u,
  ];
  if (forbidden.some((pattern) => pattern.test(source))) {
    throw new Error("Phala SDK runtime capsule contains a forbidden direct capability");
  }
}

export function verifyReviewedPhalaSdkRuntimeCapsuleMaterial({
  authorityBytes,
  registryEvidenceBytes,
  capsuleBytes,
  legalNoticeBytes,
  cloudTarballBytes,
  dstackTarballBytes,
} = {}) {
  const authority = exactAuthority(authorityBytes);
  exactRegistryEvidence(registryEvidenceBytes, authority);
  if (!Buffer.isBuffer(capsuleBytes)
    || capsuleBytes.length !== authority.capsule.byte_length
    || sha256(capsuleBytes) !== authority.capsule.sha256) {
    throw new Error("Phala SDK runtime capsule bytes differ from the reviewed static pin");
  }
  assertReviewedCapsuleSourceCapabilityBoundary(capsuleBytes);
  if (!Buffer.isBuffer(legalNoticeBytes)
    || legalNoticeBytes.length !== authority.legal_notice.byte_length
    || sha256(legalNoticeBytes) !== authority.legal_notice.sha256) {
    throw new Error("Phala SDK runtime capsule legal notice differs from its reviewed pin");
  }
  for (const [label, bytes, source] of [
    ["Phala Cloud source tarball", cloudTarballBytes, authority.source_packages.phala_cloud],
    ["Phala dstack source tarball", dstackTarballBytes, authority.source_packages.dstack_sdk],
  ]) {
    if (!Buffer.isBuffer(bytes) || sha256(bytes) !== source.tarball_sha256) {
      throw new Error(`${label} digest differs from the reviewed source package`);
    }
    exactSri(bytes, source.npm_dist_integrity_sha512, label);
  }
  return Object.freeze({
    authority_sha256: PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SHA256,
    capsule_sha256: PHALA_SDK_RUNTIME_CAPSULE_SHA256,
    request_policy_sha256: PHALA_SDK_ACTION_REQUEST_POLICY_SHA256,
    registry_evidence_sha256: PHALA_SDK_UPSTREAM_REGISTRY_EVIDENCE_SHA256,
    phala_cloud: Object.freeze({ ...authority.source_packages.phala_cloud }),
    dstack_sdk: Object.freeze({ ...authority.source_packages.dstack_sdk }),
  });
}

function projectVerifiedCompatibilityIdentity(verified) {
  return {
    node_runtime_version: PHALA_REVIEWED_NODE_RUNTIME.version,
    node_runtime_executable_realpath:
      PHALA_REVIEWED_NODE_RUNTIME.executable_realpath,
    node_runtime_executable_sha256:
      PHALA_REVIEWED_NODE_RUNTIME.executable_sha256,
    node_runtime_executable_byte_length:
      PHALA_REVIEWED_NODE_RUNTIME.executable_byte_length,
    node_runtime_ownership_status:
      PHALA_REVIEWED_NODE_RUNTIME.ownership_status,
    sdk_runtime_capsule_schema: PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SCHEMA,
    sdk_runtime_capsule_authority_sha256: verified.authority_sha256,
    sdk_runtime_capsule_sha256: verified.capsule_sha256,
    sdk_action_request_policy_sha256: verified.request_policy_sha256,
    sdk_upstream_registry_evidence_sha256: verified.registry_evidence_sha256,
    phala_cloud_version: verified.phala_cloud.package_version,
    phala_cloud_source_package_manifest_sha256:
      verified.phala_cloud.package_manifest_sha256,
    phala_cloud_source_module_sha256: verified.phala_cloud.module_sha256,
    phala_cloud_module_sha256: verified.phala_cloud.module_sha256,
    phala_cloud_source_tarball_sha256: verified.phala_cloud.tarball_sha256,
    phala_cloud_npm_dist_integrity_sha512:
      verified.phala_cloud.npm_dist_integrity_sha512,
    dstack_sdk_version: verified.dstack_sdk.package_version,
    dstack_source_package_manifest_sha256:
      verified.dstack_sdk.package_manifest_sha256,
    dstack_source_compose_hash_module_sha256:
      verified.dstack_sdk.compose_hash_module_sha256,
    dstack_source_verify_module_sha256:
      verified.dstack_sdk.verify_module_sha256,
    dstack_source_encryption_module_sha256:
      verified.dstack_sdk.encryption_module_sha256,
    dstack_encryption_module_sha256:
      verified.dstack_sdk.encryption_module_sha256,
    dstack_source_tarball_sha256: verified.dstack_sdk.tarball_sha256,
    dstack_npm_dist_integrity_sha512:
      verified.dstack_sdk.npm_dist_integrity_sha512,
  };
}

function verifyReviewedNodeRuntime() {
  if (typeof process.getuid !== "function" || process.getuid() === 0) {
    throw new Error("reviewed Node runtime boundary requires a non-root operator EUID");
  }
  const unsafeExecArg = process.execArgv.find((argument) => (
    /^(?:-(?:e|p|r)(?:.|$)|-i(?:=|$)|--(?:eval|print|interactive|require|import|loader|experimental-loader|inspect|inspect-brk|inspect-wait)(?:=|$))/u
      .test(argument)
  ));
  if (unsafeExecArg !== undefined) {
    throw new Error("reviewed Node runtime was started with an unsafe preload or inspector flag");
  }
  const real = fs.realpathSync.native(process.execPath);
  if (process.version !== PHALA_REVIEWED_NODE_RUNTIME.version
    || real !== PHALA_REVIEWED_NODE_RUNTIME.executable_realpath) {
    throw new Error("producer is not running under the reviewed absolute Node runtime");
  }
  const file = readStableReviewedFile(real, "reviewed Node executable", MAX_NODE_BYTES);
  if (file.sha256 !== PHALA_REVIEWED_NODE_RUNTIME.executable_sha256
    || file.bytes.length !== PHALA_REVIEWED_NODE_RUNTIME.executable_byte_length
    || (file.mode & 0o777n) !== 0o555n) {
    throw new Error("reviewed Node executable bytes or mode drifted");
  }
}

export function loadReviewedPhalaSdkRuntimeCapsule() {
  verifyReviewedNodeRuntime();
  const authorityFile = readStableReviewedFile(
    AUTHORITY_PATH,
    "Phala SDK runtime capsule authority",
    MAX_AUTHORITY_BYTES,
  );
  const registryEvidenceFile = readStableReviewedFile(
    REGISTRY_EVIDENCE_PATH,
    "Phala SDK upstream registry evidence",
    MAX_REGISTRY_EVIDENCE_BYTES,
  );
  const capsuleFile = readStableReviewedFile(
    CAPSULE_PATH,
    "Phala SDK runtime capsule",
    MAX_CAPSULE_BYTES,
  );
  const legalNoticeFile = readStableReviewedFile(
    LEGAL_NOTICE_PATH,
    "Phala SDK runtime capsule legal notice",
    MAX_LEGAL_NOTICE_BYTES,
  );
  const cloudTarball = readStableReviewedFile(
    CLOUD_TARBALL_PATH,
    "Phala Cloud source tarball",
    MAX_TARBALL_BYTES,
  );
  const dstackTarball = readStableReviewedFile(
    DSTACK_TARBALL_PATH,
    "Phala dstack source tarball",
    MAX_TARBALL_BYTES,
  );
  const verified = verifyReviewedPhalaSdkRuntimeCapsuleMaterial({
    authorityBytes: authorityFile.bytes,
    registryEvidenceBytes: registryEvidenceFile.bytes,
    capsuleBytes: capsuleFile.bytes,
    legalNoticeBytes: legalNoticeFile.bytes,
    cloudTarballBytes: cloudTarball.bytes,
    dstackTarballBytes: dstackTarball.bytes,
  });
  if (JSON.stringify(sorted(projectVerifiedCompatibilityIdentity(verified)))
      !== JSON.stringify(sorted(PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY))) {
    throw new Error("reviewed capsule authority differs from its compatibility identity pin");
  }
  const identity = Object.freeze({
    schema: PHALA_SDK_RUNTIME_CAPSULE_AUTHORITY_SCHEMA,
    authority_sha256: verified.authority_sha256,
    capsule_sha256: verified.capsule_sha256,
    request_policy_sha256: verified.request_policy_sha256,
    node_runtime: PHALA_REVIEWED_NODE_RUNTIME,
    phala_cloud: verified.phala_cloud,
    dstack_sdk: verified.dstack_sdk,
  });
  CAPSULE_IDENTITY.add(identity);
  CAPSULE_STATE.set(identity, {
    bytes: Buffer.from(capsuleFile.bytes),
    modulePromise: null,
  });
  return identity;
}

export function assertReviewedPhalaSdkRuntimeCapsuleIdentity(value) {
  if (!value || !CAPSULE_IDENTITY.has(value) || !CAPSULE_STATE.has(value)) {
    throw new Error("a locally verified reviewed Phala SDK runtime capsule is required");
  }
  return value;
}

export async function importReviewedPhalaSdkRuntimeCapsule(identity) {
  assertReviewedPhalaSdkRuntimeCapsuleIdentity(identity);
  const state = CAPSULE_STATE.get(identity);
  if (state.modulePromise === null) {
    const dataUrl = `data:text/javascript;base64,${state.bytes.toString("base64")}`;
    state.modulePromise = import(dataUrl).then((module) => {
      if (JSON.stringify(Object.keys(module).sort())
          !== JSON.stringify(PHALA_REVIEWED_CAPSULE_EXPORTS)) {
        throw new Error("reviewed Phala SDK runtime capsule exports drifted");
      }
      for (const name of PHALA_REVIEWED_CAPSULE_EXPORTS) {
        if (typeof module[name] !== "function") {
          throw new Error("reviewed Phala SDK runtime capsule export is not callable");
        }
      }
      return module;
    });
    state.bytes.fill(0);
  }
  return state.modulePromise;
}
