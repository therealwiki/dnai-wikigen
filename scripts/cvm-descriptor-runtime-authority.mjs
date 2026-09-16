import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";

import {
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_LAUNCH_DESCRIPTOR_FILES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  PHALA_CVM_APP_COMPOSE_NAMES,
  createPhalaDstackComposeHashInput,
  phalaDstackComposeHash,
} from "./cvm-launch-intent-core.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  cvmReleaseDescriptorSetReceiptSha256,
  validateCanonicalGeneratedCvmDescriptorSet,
} from "./cvm-release-descriptor-set.mjs";
import {
  CVM_DESCRIPTOR_EXTERNAL_RUNTIME_AUTHORITY_REQUIREMENTS,
  CVM_DESCRIPTOR_MAX_BYTES,
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_LIFETIME_MS,
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
  CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES,
  CVM_DESCRIPTOR_STABLE_READ_POLICY,
  canonicalCvmDescriptorRuntimeAuthorityText,
  createCvmDescriptorDomainRuntimeFacts,
  cvmDescriptorRuntimeAuthoritySha256,
  cvmDescriptorRuntimeFactsSha256,
  normalizeCvmDescriptorRuntimeAuthority,
} from "./cvm-descriptor-runtime-authority-core.mjs";

export {
  CVM_DESCRIPTOR_DOMAIN_RUNTIME_FACTS_DOMAIN,
  CVM_DESCRIPTOR_EXTERNAL_RUNTIME_AUTHORITY_REQUIREMENTS,
  CVM_DESCRIPTOR_MAX_BYTES,
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_DOMAIN,
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_LIFETIME_MS,
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
  CVM_DESCRIPTOR_RUNTIME_FACTS_DOMAIN,
  CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES,
  CVM_DESCRIPTOR_STABLE_READ_POLICY,
  canonicalCvmDescriptorRuntimeAuthorityText,
  createCvmDescriptorDomainRuntimeFacts,
  cvmDescriptorDomainRuntimeFactsSha256,
  cvmDescriptorRuntimeAuthoritySha256,
  cvmDescriptorRuntimeFactsSha256,
  normalizeCvmDescriptorDomainRuntimeFacts,
  normalizeCvmDescriptorRuntimeAuthority,
} from "./cvm-descriptor-runtime-authority-core.mjs";

const MAX_DESCRIPTOR_BYTES = CVM_DESCRIPTOR_MAX_BYTES;
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const INTERPOLATION = /^\$\{([A-Z][A-Z0-9_]{0,127})(:\?|:-)([^{}\r\n]*)\}$/;
const IMAGE_REFERENCE =
  /^ghcr\.io\/therealwiki\/dnai-wikigen\/[a-z0-9-]+@sha256:(?!0{64}$)[0-9a-f]{64}$/;
const FRESH_RUNTIME_AUTHORITIES = new WeakMap();
const FRESH_RUNTIME_MATERIAL_SETS = new WeakMap();

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sameBigIntStat(before, after, { includeSize = true } = {}) {
  return before.dev === after.dev
    && before.ino === after.ino
    && (!includeSize || before.size === after.size)
    && before.mode === after.mode
    && before.uid === after.uid
    && before.gid === after.gid
    && before.nlink === after.nlink
    && before.mtimeNs === after.mtimeNs
    && before.ctimeNs === after.ctimeNs;
}

function assertOwnedNonWritableStat(stat, label, { file = false } = {}) {
  const effectiveUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : null;
  if ((file ? !stat.isFile() : !stat.isDirectory())
    || (file && stat.nlink !== 1n)
    || (stat.mode & 0o022n) !== 0n
    || (effectiveUid !== null && stat.uid !== effectiveUid)) {
    throw new Error(`${label} must be owned, non-writable-by-group-or-world, and link-safe`);
  }
}

async function openStableReleaseDirectory(releaseDirectory) {
  const resolved = path.resolve(releaseDirectory || "");
  if (path.basename(resolved) !== ".release" || await realpath(resolved) !== resolved) {
    throw new Error("descriptor runtime authority requires one exact non-symlink .release directory");
  }
  const handle = await open(
    resolved,
    fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY || 0) | fsConstants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat({ bigint: true });
    assertOwnedNonWritableStat(before, "descriptor release directory");
    const named = await lstat(resolved, { bigint: true });
    if (!sameBigIntStat(before, named, { includeSize: false })) {
      throw new Error("descriptor release directory path identity is unstable");
    }
    return { resolved, handle, before };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function readStableOwnedDescriptor(directory, filename, label) {
  const resolved = path.join(directory, filename);
  if (path.dirname(resolved) !== directory || await realpath(resolved) !== resolved) {
    throw new Error(`${label} path must not contain symbolic links`);
  }
  const handle = await open(resolved, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    assertOwnedNonWritableStat(before, label, { file: true });
    if (before.size < 2n || before.size > BigInt(MAX_DESCRIPTOR_BYTES)) {
      throw new Error(`${label} must be bounded and nonempty`);
    }
    const namedBefore = await lstat(resolved, { bigint: true });
    if (!sameBigIntStat(before, namedBefore)) {
      throw new Error(`${label} path identity differs from its open file`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const namedAfter = await lstat(resolved, { bigint: true });
    if (BigInt(bytes.length) !== before.size
      || !sameBigIntStat(before, after)
      || !sameBigIntStat(before, namedAfter)
      || await realpath(resolved) !== resolved) {
      throw new Error(`${label} changed during its stable read`);
    }
    const text = bytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(bytes) || text.includes("\0")) {
      throw new Error(`${label} is not exact canonical UTF-8 text`);
    }
    return { bytes, text, sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}` };
  } finally {
    await handle.close();
  }
}

function parseDescriptorDocument(text, domain) {
  const body = text.split("\n").slice(3).join("\n");
  let document;
  try {
    document = JSON.parse(body);
  } catch {
    throw new Error(`${domain} descriptor body changed after canonical validation`);
  }
  if (!isRecord(document) || !isRecord(document.services)
    || document.name !== PHALA_CVM_APP_COMPOSE_NAMES[domain]
    || document["x-dnai-release"]?.trust_domain !== domain) {
    throw new Error(`${domain} stable descriptor identity is invalid`);
  }
  return document;
}

function collectDescriptorEnvironmentKeys(value, output) {
  if (Array.isArray(value)) {
    value.forEach((entry) => collectDescriptorEnvironmentKeys(entry, output));
    return;
  }
  if (isRecord(value)) {
    Object.values(value).forEach((entry) => collectDescriptorEnvironmentKeys(entry, output));
    return;
  }
  if (typeof value !== "string" || !value.startsWith("${")) return;
  const match = value.match(INTERPOLATION);
  if (!match) throw new Error("stable descriptor contains a noncanonical environment interpolation");
  output.add(match[1]);
}

function projectDomainFacts(domain, file) {
  const document = parseDescriptorDocument(file.text, domain);
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const serviceImages = CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain].map((service) => {
    const image = document.services[service]?.image;
    if (typeof image !== "string" || !IMAGE_REFERENCE.test(image)) {
      throw new Error(`${domain}.${service} stable image reference is invalid`);
    }
    return { service, image };
  });
  const environmentKeys = new Set();
  collectDescriptorEnvironmentKeys(document, environmentKeys);
  const appCompose = createPhalaDstackComposeHashInput(
    policy.app_compose_candidate,
    file.text,
    policy.exact_allowed_environment_keys,
  );
  return createCvmDescriptorDomainRuntimeFacts({
    domain,
    descriptorSha256: file.sha256,
    descriptorByteLength: file.bytes.length,
    appComposeHash: phalaDstackComposeHash(appCompose),
    serviceImages,
    descriptorEnvironmentKeys: [...environmentKeys],
  });
}

export async function createFreshCvmDescriptorRuntimeAuthority(input = {}) {
  const options = exactRecord(
    input,
    ["releaseDirectory", "expectedReleaseSha"],
    "fresh descriptor runtime authority input",
  );
  if (typeof options.expectedReleaseSha !== "string"
    || !SHA40.test(options.expectedReleaseSha)) {
    throw new Error("expected release SHA must be nonzero lowercase 40-hex");
  }
  const readStartedAt = new Date(Date.now()).toISOString();
  const descriptorSetReceipt = await validateCanonicalGeneratedCvmDescriptorSet({
    releaseDirectory: options.releaseDirectory,
    expectedReleaseSha: options.expectedReleaseSha,
  });
  const directory = await openStableReleaseDirectory(options.releaseDirectory);
  try {
    const descriptors = [];
    for (const domain of CVM_LAUNCH_DOMAINS) {
      const file = await readStableOwnedDescriptor(
        directory.resolved,
        CVM_LAUNCH_DESCRIPTOR_FILES[domain],
        `${domain} runtime descriptor`,
      );
      if (file.sha256 !== descriptorSetReceipt.descriptor_sha256_by_domain[domain]) {
        throw new Error(`${domain} bytes changed after canonical descriptor-set validation`);
      }
      descriptors.push(projectDomainFacts(domain, file));
    }
    const after = await directory.handle.stat({ bigint: true });
    const namedAfter = await lstat(directory.resolved, { bigint: true });
    if (!sameBigIntStat(directory.before, after, { includeSize: false })
      || !sameBigIntStat(directory.before, namedAfter, { includeSize: false })
      || await realpath(directory.resolved) !== directory.resolved) {
      throw new Error("descriptor release directory changed during exact seven-file read");
    }
    const readCompletedMs = Date.now();
    const authority = {
      schema: CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
      status: "fresh_stable_descriptor_runtime_authority",
      truth_status:
        "fresh_local_descriptor_bytes_and_reviewed_launch_policy_not_phala_deployment_runtime_or_tdx_evidence",
      release_sha: descriptorSetReceipt.release_sha,
      source_ref: descriptorSetReceipt.source_ref,
      descriptor_set_receipt_schema: CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
      descriptor_set_receipt_sha256:
        cvmReleaseDescriptorSetReceiptSha256(descriptorSetReceipt),
      image_manifest_sha256: descriptorSetReceipt.image_manifest_sha256,
      topology_sha256: descriptorSetReceipt.topology_sha256,
      descriptor_sha256_by_domain: Object.fromEntries(descriptors.map((entry) => [
        entry.domain,
        entry.descriptor_sha256,
      ])),
      app_compose_hash_by_domain: Object.fromEntries(descriptors.map((entry) => [
        entry.domain,
        entry.app_compose_hash,
      ])),
      descriptor_runtime_facts_sha256: null,
      stable_read_policy: structuredClone(CVM_DESCRIPTOR_STABLE_READ_POLICY),
      fact_sources: structuredClone(CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES),
      external_runtime_authority_requirements: structuredClone(
        CVM_DESCRIPTOR_EXTERNAL_RUNTIME_AUTHORITY_REQUIREMENTS,
      ),
      descriptors,
      read_started_at: readStartedAt,
      read_completed_at: new Date(readCompletedMs).toISOString(),
      expires_at: new Date(
        readCompletedMs + CVM_DESCRIPTOR_RUNTIME_AUTHORITY_LIFETIME_MS,
      ).toISOString(),
      invariants: {
        exact_seven_canonical_files: true,
        raw_descriptor_bytes_freshly_stable_read: true,
        descriptor_set_receipt_revalidated: true,
        caller_supplied_descriptor_hashes_or_facts: false,
        symlinks_or_hardlinks: false,
        group_or_world_writable_files: false,
        runtime_resource_or_identity_claimed: false,
        deployment_or_tdx_claimed: false,
      },
    };
    authority.descriptor_runtime_facts_sha256 = cvmDescriptorRuntimeFactsSha256(authority);
    const normalized = normalizeCvmDescriptorRuntimeAuthority(authority);
    const digest = cvmDescriptorRuntimeAuthoritySha256(normalized);
    FRESH_RUNTIME_AUTHORITIES.set(normalized, digest);
    return normalized;
  } finally {
    await directory.handle.close();
  }
}

/**
 * Re-reads the exact descriptor bytes behind a fresh runtime authority for the
 * production SDK request builder. The returned compose material is privately
 * associated with that authority; a caller cannot substitute text while
 * retaining the material-set brand.
 */
export async function readFreshCvmDescriptorRuntimeMaterials(input = {}) {
  const options = exactRecord(
    input,
    ["authority", "releaseDirectory"],
    "fresh descriptor runtime material input",
  );
  const authority = assertFreshCvmDescriptorRuntimeAuthority(options.authority);
  const directory = await openStableReleaseDirectory(options.releaseDirectory);
  try {
    const materials = [];
    for (const domain of CVM_LAUNCH_DOMAINS) {
      const facts = authority.descriptors.find((entry) => entry.domain === domain);
      if (!facts) throw new Error(`${domain} runtime facts are absent`);
      const file = await readStableOwnedDescriptor(
        directory.resolved,
        CVM_LAUNCH_DESCRIPTOR_FILES[domain],
        `${domain} runtime descriptor material`,
      );
      const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
      const appCompose = createPhalaDstackComposeHashInput(
        policy.app_compose_candidate,
        file.text,
        policy.exact_allowed_environment_keys,
      );
      if (file.sha256 !== facts.descriptor_sha256
        || file.bytes.length !== facts.descriptor_byte_length
        || phalaDstackComposeHash(appCompose) !== facts.app_compose_hash) {
        throw new Error(`${domain} descriptor material drifted from its fresh authority`);
      }
      materials.push({
        domain,
        descriptor_file: CVM_LAUNCH_DESCRIPTOR_FILES[domain],
        descriptor_sha256: file.sha256,
        docker_compose_file: file.text,
        allowed_environment_keys: [...policy.exact_allowed_environment_keys],
        app_compose_hash: facts.app_compose_hash,
      });
    }
    const after = await directory.handle.stat({ bigint: true });
    const namedAfter = await lstat(directory.resolved, { bigint: true });
    if (!sameBigIntStat(directory.before, after, { includeSize: false })
      || !sameBigIntStat(directory.before, namedAfter, { includeSize: false })
      || await realpath(directory.resolved) !== directory.resolved) {
      throw new Error("descriptor release directory changed during runtime material read");
    }
    const result = deepFreezeCanonicalPlainDataGraph(materials, {
      label: "fresh CVM descriptor runtime materials",
    });
    FRESH_RUNTIME_MATERIAL_SETS.set(result, Object.freeze({
      authority,
      authority_sha256: cvmDescriptorRuntimeAuthoritySha256(authority),
    }));
    return result;
  } finally {
    await directory.handle.close();
  }
}

export function assertFreshCvmDescriptorRuntimeMaterials(value, { authority } = {}) {
  const provenance = value && FRESH_RUNTIME_MATERIAL_SETS.get(value);
  const expected = assertFreshCvmDescriptorRuntimeAuthority(authority);
  if (!provenance || provenance.authority !== expected
    || provenance.authority_sha256 !== cvmDescriptorRuntimeAuthoritySha256(expected)
    || !Array.isArray(value) || value.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("fresh runtime descriptor materials do not match their branded authority");
  }
  return value;
}

export function assertFreshCvmDescriptorRuntimeAuthority(value, {
  expectedReleaseSha,
  expectedDescriptorSetReceiptSha256,
} = {}) {
  const brandedDigest = value && FRESH_RUNTIME_AUTHORITIES.get(value);
  if (!brandedDigest) {
    throw new Error("a privately branded fresh stable-read descriptor runtime authority is required");
  }
  const normalized = normalizeCvmDescriptorRuntimeAuthority(value);
  const actualDigest = cvmDescriptorRuntimeAuthoritySha256(normalized);
  if (actualDigest !== brandedDigest
    || canonicalCvmDescriptorRuntimeAuthorityText(normalized)
      !== canonicalCvmDescriptorRuntimeAuthorityText(value)
    || Date.now() > Date.parse(normalized.expires_at)
    || (expectedReleaseSha !== undefined
      && normalized.release_sha !== expectedReleaseSha)
    || (expectedDescriptorSetReceiptSha256 !== undefined
      && normalized.descriptor_set_receipt_sha256
        !== expectedDescriptorSetReceiptSha256)) {
    throw new Error("fresh descriptor runtime authority brand, digest, freshness, or expected binding failed");
  }
  return value;
}
