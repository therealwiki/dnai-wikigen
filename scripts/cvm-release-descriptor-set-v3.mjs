#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { mkdtemp, mkdir, open, realpath, rm } from "node:fs/promises";
import { execFile } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  parseCanonicalPublicHttpsUrl,
} from "./canonical-public-https-url-core.mjs";

import {
  CVM_LAUNCH_DESCRIPTOR_FILES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS,
  PHALA_CVM_APP_COMPOSE_NAMES,
} from "./cvm-launch-intent-core.mjs";
import {
  IMAGE_NAMES,
  PLATFORM as IMAGE_PLATFORM,
  RELEASE_SCHEMA as IMAGE_RELEASE_SCHEMA,
} from "./build-tee-image-release.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_GENERATED_FILES,
  CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_DOMAIN,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  CVM_RELEASE_DESCRIPTOR_TRACKED_SOURCE_FILES,
} from "./cvm-release-descriptor-set-constants-v3.mjs";

export {
  CVM_RELEASE_DESCRIPTOR_GENERATED_FILES,
  CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_DOMAIN,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  CVM_RELEASE_DESCRIPTOR_TRACKED_SOURCE_FILES,
} from "./cvm-release-descriptor-set-constants-v3.mjs";

const execFileAsync = promisify(execFile);
const RELEASE_SHA = /^[0-9a-f]{40}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const IMAGE_REFERENCE = /^ghcr\.io\/therealwiki\/dnai-wikigen\/([a-z0-9-]+)@sha256:([0-9a-f]{64})$/;
const ENVIRONMENT_KEY = /^[A-Z][A-Z0-9_]{0,127}$/;
const INTERPOLATION = /^\$\{([A-Z][A-Z0-9_]{0,127})(:\?|:-)([^{}\r\n]*)\}$/;
const INTERPOLATION_OCCURRENCE = /(?<!\$)\$\{([A-Z][A-Z0-9_]{0,127})([^{}\r\n]*)\}/g;
const MAX_PUBLIC_ARTIFACT_BYTES = 4 * 1024 * 1024;
const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME =
  "tinker-account-binding-ceremony.receipt.json";
const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SCHEMA =
  "dnai.tinker-account-binding-ceremony-receipt.v1";
const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD =
  "tinker_account_binding_ceremony_receipt_sha256";
const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_TOPOLOGY_VALIDATION =
  "python_structural_and_domain_digest_binding_requires_node_ceremony_check_replay";
const PUBLIC_SECRET_MARKERS = [
  /PHALA_CLOUD_API_KEY/,
  /-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----/,
  /(?:^|[^A-Za-z0-9])phak_[A-Za-z0-9_-]{8,}/,
];

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys, label) {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.join("\0") !== expected.join("\0")) {
    throw new Error(`${label} fields are not exact`);
  }
  return value;
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function sameStringSet(actual, expected) {
  return Array.isArray(actual)
    && actual.every((value) => typeof value === "string")
    && actual.length === new Set(actual).size
    && [...actual].sort().join("\0") === [...expected].sort().join("\0");
}

function canonicalSortedValue(value) {
  if (Array.isArray(value)) return value.map(canonicalSortedValue);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalSortedValue(value[key])]),
  );
}

function canonicalSortedJsonText(value) {
  return `${JSON.stringify(canonicalSortedValue(value), null, 2)}\n`;
}

function sha256Digest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)
    || value === `sha256:${"0".repeat(64)}`) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

export function normalizeCvmReleaseDescriptorSetReceipt(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "CVM release descriptor-set receipt",
  });
  const parsed = exactKeys(value, [
    "schema",
    "status",
    "truth_status",
    "materialization_boundary",
    "release_sha",
    "source_ref",
    "image_manifest_sha256",
    "image_manifest_sigstore_bundle_sha256",
    "topology_sha256",
    "tinker_account_binding_ceremony_receipt_sha256",
    "descriptor_sha256_by_domain",
    "service_matrix",
    "image_references",
    "invariants",
  ], "CVM release descriptor-set receipt");
  if (parsed.schema !== CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA
    || parsed.status !== "validated_rendered_not_deployed"
    || parsed.truth_status
      !== "descriptor_consistency_not_cvm_creation_tdx_or_runtime_evidence"
    || JSON.stringify(parsed.materialization_boundary)
      !== JSON.stringify(CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY)
    || typeof parsed.release_sha !== "string" || !RELEASE_SHA.test(parsed.release_sha)
    || typeof parsed.source_ref !== "string"
    || !/^refs\/(?:heads\/main|tags\/v[0-9][0-9A-Za-z._-]*)$/.test(parsed.source_ref)) {
    throw new Error("CVM release descriptor-set receipt authority is invalid");
  }
  const descriptorSha256ByDomain = exactKeys(
    parsed.descriptor_sha256_by_domain,
    CVM_LAUNCH_DOMAINS,
    "CVM release descriptor-set receipt descriptor map",
  );
  const normalizedDescriptorMap = Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [
    domain,
    sha256Digest(
      descriptorSha256ByDomain[domain],
      `CVM release descriptor-set receipt ${domain} descriptor`,
    ),
  ]));
  if (new Set(Object.values(normalizedDescriptorMap)).size !== CVM_LAUNCH_DOMAINS.length
    || JSON.stringify(parsed.service_matrix)
      !== JSON.stringify(CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX)
    || !Array.isArray(parsed.image_references)
    || parsed.image_references.length !== IMAGE_NAMES.length
    || parsed.image_references.some((reference) => (
      typeof reference !== "string" || !IMAGE_REFERENCE.test(reference)
    ))
    || new Set(parsed.image_references).size !== IMAGE_NAMES.length) {
    throw new Error("CVM release descriptor-set receipt domain or image set is invalid");
  }
  const invariants = exactKeys(parsed.invariants, [
    "all_seven_generated_files_present",
    "exact_raw_hashes_bound_by_topology",
    "exact_service_matrices",
    "exact_clean_ci_image_digests",
    "embedded_secret_values",
    "deployment_claimed",
    "tdx_attestation_claimed",
  ], "CVM release descriptor-set receipt invariants");
  if (invariants.all_seven_generated_files_present !== true
    || invariants.exact_raw_hashes_bound_by_topology !== true
    || invariants.exact_service_matrices !== true
    || invariants.exact_clean_ci_image_digests !== true
    || invariants.embedded_secret_values !== false
    || invariants.deployment_claimed !== false
    || invariants.tdx_attestation_claimed !== false) {
    throw new Error("CVM release descriptor-set receipt invariants are invalid");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
    status: "validated_rendered_not_deployed",
    truth_status:
      "descriptor_consistency_not_cvm_creation_tdx_or_runtime_evidence",
    materialization_boundary: structuredClone(
      CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
    ),
    release_sha: parsed.release_sha,
    source_ref: parsed.source_ref,
    image_manifest_sha256: sha256Digest(
      parsed.image_manifest_sha256,
      "CVM release descriptor-set receipt image manifest",
    ),
    image_manifest_sigstore_bundle_sha256: sha256Digest(
      parsed.image_manifest_sigstore_bundle_sha256,
      "CVM release descriptor-set receipt Sigstore bundle",
    ),
    topology_sha256: sha256Digest(
      parsed.topology_sha256,
      "CVM release descriptor-set receipt topology",
    ),
    tinker_account_binding_ceremony_receipt_sha256: sha256Digest(
      parsed.tinker_account_binding_ceremony_receipt_sha256,
      "CVM release descriptor-set receipt Tinker account-binding ceremony receipt",
    ),
    descriptor_sha256_by_domain: normalizedDescriptorMap,
    service_matrix: structuredClone(CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX),
    image_references: [...parsed.image_references],
    invariants: {
      all_seven_generated_files_present: true,
      exact_raw_hashes_bound_by_topology: true,
      exact_service_matrices: true,
      exact_clean_ci_image_digests: true,
      embedded_secret_values: false,
      deployment_claimed: false,
      tdx_attestation_claimed: false,
    },
  }, { label: "normalized CVM release descriptor-set receipt" });
}

export function canonicalCvmReleaseDescriptorSetReceiptText(value) {
  return canonicalSortedJsonText(normalizeCvmReleaseDescriptorSetReceipt(value));
}

export function cvmReleaseDescriptorSetReceiptSha256(value) {
  return `sha256:${createHash("sha256")
    .update(CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_DOMAIN, "utf8")
    .update(canonicalCvmReleaseDescriptorSetReceiptText(value), "utf8")
    .digest("hex")}`;
}

function exactReleaseSha(value, label = "release SHA") {
  if (typeof value !== "string" || !RELEASE_SHA.test(value)) {
    throw new Error(`${label} must be 40 lowercase hexadecimal characters`);
  }
  return value;
}

async function readStablePublicFile(filePath, label, maximum = MAX_PUBLIC_ARTIFACT_BYTES) {
  const resolved = path.resolve(filePath);
  if (await realpath(resolved) !== resolved) {
    throw new Error(`${label} path must not contain symbolic links`);
  }
  const handle = await open(resolved, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1
      || before.size < 2 || before.size > maximum
      || (before.mode & 0o022) !== 0
      || (typeof process.getuid === "function" && before.uid !== process.getuid())) {
      throw new Error(`${label} must be a bounded nonempty regular file`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size
      || after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs
      || after.mode !== before.mode
      || after.uid !== before.uid
      || after.nlink !== before.nlink
      || await realpath(resolved) !== resolved) {
      throw new Error(`${label} changed during stable read`);
    }
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.length || text.includes("\0")) {
      throw new Error(`${label} is not canonical UTF-8 text`);
    }
    return Object.freeze({ path: resolved, bytes, text, sha256: sha256(bytes) });
  } finally {
    await handle.close();
  }
}

function parseJson(text, label) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  return value;
}

function assertNoPublicSecretMarkers(text, label) {
  for (const marker of PUBLIC_SECRET_MARKERS) {
    if (marker.test(text)) throw new Error(`${label} contains forbidden credential material`);
  }
}

function normalizeReleaseManifest(text, expectedReleaseSha) {
  assertNoPublicSecretMarkers(text, "image release manifest");
  const manifest = exactKeys(parseJson(text, "image release manifest"), [
    "schema",
    "release_sha",
    "source_ref",
    "generated_at",
    "source_repository",
    "signer_workflow",
    "workflow_run_id",
    "workflow_run_url",
    "platform",
    "images",
  ], "image release manifest");
  const generatedAt = new Date(manifest.generated_at);
  if (manifest.schema !== IMAGE_RELEASE_SCHEMA
    || manifest.release_sha !== expectedReleaseSha
    || manifest.source_repository !== "therealwiki/dnai-wikigen"
    || manifest.signer_workflow
      !== "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml"
    || manifest.platform !== IMAGE_PLATFORM
    || Number.isNaN(generatedAt.getTime())
    || generatedAt.toISOString() !== manifest.generated_at
    || !/^[1-9][0-9]*$/.test(manifest.workflow_run_id)
    || manifest.workflow_run_url
      !== `https://github.com/therealwiki/dnai-wikigen/actions/runs/${manifest.workflow_run_id}`
    || !/^refs\/(?:heads\/main|tags\/v[0-9][0-9A-Za-z._-]*)$/.test(manifest.source_ref)) {
    throw new Error("image release manifest authority does not match the reviewed repository release");
  }
  if (!Array.isArray(manifest.images) || manifest.images.length !== IMAGE_NAMES.length) {
    throw new Error("image release manifest must contain the five exact images");
  }
  const normalizedImages = manifest.images.map((raw, index) => {
    const image = exactKeys(raw, [
      "name",
      "repository",
      "digest",
      "image",
      "platform",
      "sbom_artifact",
      "provenance_subject",
      "attestations",
      "verification",
    ], `image release manifest image ${index}`);
    const expectedName = IMAGE_NAMES[index];
    const expectedRepository = `ghcr.io/therealwiki/dnai-wikigen/${expectedName}`;
    if (image.name !== expectedName
      || image.repository !== expectedRepository
      || !SHA256.test(image.digest)
      || image.digest === `sha256:${"0".repeat(64)}`
      || image.image !== `${expectedRepository}@${image.digest}`
      || image.platform !== IMAGE_PLATFORM) {
      throw new Error(`image release manifest image ${expectedName} is not exact and digest-pinned`);
    }
    const provenance = exactKeys(image.provenance_subject, ["name", "digest"], `${expectedName} provenance subject`);
    if (provenance.name !== expectedRepository || provenance.digest !== image.digest) {
      throw new Error(`${expectedName} provenance subject does not match its image`);
    }
    const sbomArtifact = exactKeys(
      image.sbom_artifact,
      ["filename", "sha256"],
      `${expectedName} SBOM artifact`,
    );
    if (sbomArtifact.filename !== `${expectedName}.spdx.json`
      || !BARE_SHA256.test(sbomArtifact.sha256)
      || sbomArtifact.sha256 === "0".repeat(64)) {
      throw new Error(`${expectedName} SBOM artifact binding is invalid`);
    }
    const attestations = exactKeys(
      image.attestations,
      ["provenance", "sbom"],
      `${expectedName} attestations`,
    );
    for (const [kind, predicate] of [
      ["provenance", "https://slsa.dev/provenance/v1"],
      ["sbom", "https://spdx.dev/Document/v2.3"],
    ]) {
      const attestation = exactKeys(
        attestations[kind],
        ["predicate_type", "id", "url"],
        `${expectedName} ${kind} attestation`,
      );
      const attestationUrl = parseCanonicalPublicHttpsUrl(attestation.url, {
        label: `${expectedName} ${kind} attestation URL`,
        requirePath: true,
      });
      if (attestation.predicate_type !== predicate
        || !/^[1-9][0-9]*$/.test(attestation.id)
        || attestationUrl.pathname === "/") {
        throw new Error(`${expectedName} ${kind} attestation authority is invalid`);
      }
    }
    const verification = exactKeys(image.verification, [
      "repo",
      "signer_workflow",
      "source_digest",
      "source_ref",
      "provenance_attestation",
      "sbom_attestation",
    ], `${expectedName} verification`);
    if (verification.repo !== "therealwiki/dnai-wikigen"
      || verification.signer_workflow
        !== "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml"
      || verification.source_digest !== expectedReleaseSha
      || verification.source_ref !== manifest.source_ref
      || verification.provenance_attestation !== "verified"
      || verification.sbom_attestation !== "verified") {
      throw new Error(`${expectedName} does not have exact clean-CI verification`);
    }
    return Object.freeze({
      name: expectedName,
      image: image.image,
      digest: image.digest,
    });
  });
  if (new Set(normalizedImages.map((image) => image.digest)).size !== IMAGE_NAMES.length) {
    throw new Error("image release manifest digests must be pairwise distinct");
  }
  return Object.freeze({
    releaseSha: expectedReleaseSha,
    sourceRef: manifest.source_ref,
    generatedAt: manifest.generated_at,
    images: normalizedImages,
    byName: Object.freeze(Object.fromEntries(
      normalizedImages.map((image) => [image.name, image]),
    )),
  });
}

function expectedServiceImageName(domain, service) {
  if (domain.endsWith("_qvl_cvm")) return "attestation-qvl";
  if (domain === "independent_metering_cvm") return "compute-metering";
  if (service === "neko") return "neko-chrome";
  if (service === "oracle" || service === "mailbox-genesis") {
    return "tee-email-oracle";
  }
  return "tinker-delegate";
}

function parseGeneratedDescriptor(text, manifestSha256, domain) {
  assertNoPublicSecretMarkers(text, `${domain} descriptor`);
  const lines = text.split("\n");
  const expectedHeader = [
    "# Generated by tinker-release-composes. Do not edit by hand.",
    `# Input image manifest sha256: ${manifestSha256}`,
    "# Status: rendered_not_deployed; deployment and TDX verification are separate gates.",
  ];
  if (lines.slice(0, 3).join("\n") !== expectedHeader.join("\n")) {
    throw new Error(`${domain} descriptor header does not bind the exact image manifest`);
  }
  const bodyText = lines.slice(3).join("\n");
  const descriptor = parseJson(bodyText, `${domain} descriptor body`);
  if (bodyText !== canonicalSortedJsonText(descriptor)) {
    throw new Error(`${domain} descriptor body is not canonical sorted two-space JSON/YAML`);
  }
  return descriptor;
}

function collectInterpolations(value, pathLabel, output) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectInterpolations(item, `${pathLabel}[${index}]`, output));
    return;
  }
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      collectInterpolations(key, `${pathLabel}.<key>`, output);
      collectInterpolations(item, `${pathLabel}.${key}`, output);
    }
    return;
  }
  if (typeof value !== "string") return;
  INTERPOLATION_OCCURRENCE.lastIndex = 0;
  const matches = [...value.matchAll(INTERPOLATION_OCCURRENCE)];
  INTERPOLATION_OCCURRENCE.lastIndex = 0;
  const unmatched = value.replace(INTERPOLATION_OCCURRENCE, "");
  if (/(?<!\$)\$\{/.test(unmatched)) {
    throw new Error(`${pathLabel} contains a noncanonical Compose interpolation`);
  }
  for (const match of matches) {
    const rawSuffix = match[2];
    const operator = rawSuffix.startsWith(":?") || rawSuffix.startsWith(":-")
      ? rawSuffix.slice(0, 2)
      : "";
    output.push(Object.freeze({
      key: match[1],
      operator,
      suffix: operator ? rawSuffix.slice(2) : rawSuffix,
      path: pathLabel,
    }));
  }
}

function sensitiveEnvironmentKey(key) {
  if (/(?:_PATH|_FILE|_DIR)$/.test(key)) return false;
  return /(?:PASSWORD|TOKEN|SECRET|PRIVATE_KEY|API_KEY)/.test(key);
}

function validateEnvironmentSurface(domain, descriptor) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const services = descriptor.services;
  const occurrences = [];
  for (const [serviceName, service] of Object.entries(services)) {
    collectInterpolations(service, `${domain}.services.${serviceName}`, occurrences);
    const environment = service.environment || {};
    if (!isRecord(environment)) throw new Error(`${domain}.${serviceName} environment must be a mapping`);
    for (const [key, value] of Object.entries(environment)) {
      if (!ENVIRONMENT_KEY.test(key)) {
        throw new Error(`${domain}.${serviceName} has a noncanonical environment key`);
      }
      if (sensitiveEnvironmentKey(key)
        && value !== ""
        && !(typeof value === "string" && INTERPOLATION.test(value))) {
        throw new Error(`${domain}.${serviceName}.${key} embeds a nonempty secret-like value`);
      }
    }
  }
  const expectedReferences = sortedUnique([
    ...policy.exact_allowed_environment_keys.filter((key) => key !== "COMPOSE_PROFILES"),
    ...policy.public_environment_key_classification.descriptor_defaulted_keys,
  ]);
  const actualReferences = sortedUnique(occurrences.map((item) => item.key));
  if (actualReferences.join("\0") !== expectedReferences.join("\0")) {
    throw new Error(`${domain} environment references do not equal the canonical key contract`);
  }
  const bootstrapAndProvisioning = new Set([
    ...policy.encrypted_secret_environment_keys_by_phase.bootstrap_provision,
    ...policy.public_environment_key_classification.provisioning_result_keys,
  ]);
  const late = new Set([
    ...policy.public_environment_key_classification.post_measurement_deferred_keys,
    ...Object.entries(policy.encrypted_secret_environment_keys_by_phase)
      .filter(([phase]) => phase !== "bootstrap_provision")
      .flatMap(([, keys]) => keys),
  ]);
  const boundedActiveServiceLateInputs = new Set(
    CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS,
  );
  if (domain === "main_runtime_cvm") {
    for (const key of boundedActiveServiceLateInputs) {
      const matchingOccurrences = occurrences.filter((occurrence) => occurrence.key === key);
      const expectedPath = `${domain}.services.delegate.environment.${key}`;
      if (matchingOccurrences.length !== 1
        || matchingOccurrences[0].path !== expectedPath) {
        throw new Error(
          `${domain} active-service late input ${key} must occur exactly once at ${expectedPath} with the mapping key equal to ${key}`,
        );
      }
    }
  }
  for (const occurrence of occurrences) {
    if (bootstrapAndProvisioning.has(occurrence.key) && occurrence.operator !== ":?") {
      throw new Error(`${domain} bootstrap/provisioning input ${occurrence.key} is not strict nonempty`);
    }
    if (late.has(occurrence.key) && (occurrence.operator !== ":-" || occurrence.suffix !== "")) {
      throw new Error(`${domain} post-measurement input ${occurrence.key} is not exact empty-default`);
    }
    if (late.has(occurrence.key)) {
      const serviceName = occurrence.path.split(".services.")[1]?.split(".")[0];
      const profiles = services[serviceName]?.profiles || [];
      const boundedActiveDelegateInput = domain === "main_runtime_cvm"
        && serviceName === "delegate"
        && boundedActiveServiceLateInputs.has(occurrence.key);
      if (!boundedActiveDelegateInput && (!serviceName
        || policy.launch_settings.initial_services.includes(serviceName)
        || profiles.length !== 1
        || !policy.launch_settings.initially_disabled_profiles.includes(profiles[0]))) {
        throw new Error(`${domain} late input ${occurrence.key} escaped its disabled profile`);
      }
    }
  }
}

function validateDescriptorDocument(domain, descriptor, manifest, expectedReleaseSha) {
  if (!isRecord(descriptor)
    || descriptor.name !== PHALA_CVM_APP_COMPOSE_NAMES[domain]
    || !isRecord(descriptor.services)) {
    throw new Error(`${domain} descriptor name or services mapping is invalid`);
  }
  const release = exactKeys(descriptor["x-dnai-release"], [
    "schema",
    "release_sha",
    "source_ref",
    "platform",
    "trust_domain",
    "deployment_status",
  ], `${domain} release metadata`);
  if (release.schema !== "dnai.cvm-topology.v6"
    || release.release_sha !== expectedReleaseSha
    || release.source_ref !== manifest.sourceRef
    || release.platform !== IMAGE_PLATFORM
    || release.trust_domain !== domain
    || release.deployment_status !== "rendered_not_deployed") {
    throw new Error(`${domain} descriptor release metadata is not exact`);
  }
  const expectedServices = CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain];
  if (!sameStringSet(Object.keys(descriptor.services), expectedServices)) {
    throw new Error(`${domain} descriptor service matrix is not exact`);
  }
  for (const serviceName of expectedServices) {
    const service = descriptor.services[serviceName];
    if (!isRecord(service)
      || Object.hasOwn(service, "build")
      || service.platform !== IMAGE_PLATFORM) {
      throw new Error(`${domain}.${serviceName} is not a registry-only linux/amd64 service`);
    }
    const match = typeof service.image === "string" ? service.image.match(IMAGE_REFERENCE) : null;
    const expectedImageName = expectedServiceImageName(domain, serviceName);
    if (!match
      || match[1] !== expectedImageName
      || service.image !== manifest.byName[expectedImageName].image) {
      throw new Error(`${domain}.${serviceName} does not use the exact release image digest`);
    }
  }
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const active = Object.entries(descriptor.services)
    .filter(([, service]) => !Object.hasOwn(service, "profiles"))
    .map(([name]) => name);
  if (!sameStringSet(active, policy.launch_settings.initial_services)) {
    throw new Error(`${domain} initial service set is not exact`);
  }
  const profiles = [];
  for (const [name, service] of Object.entries(descriptor.services)) {
    if (!Object.hasOwn(service, "profiles")) continue;
    if (!Array.isArray(service.profiles)
      || service.profiles.length !== 1
      || typeof service.profiles[0] !== "string") {
      throw new Error(`${domain}.${name} must have one exact disabled profile`);
    }
    profiles.push(service.profiles[0]);
  }
  if (!sameStringSet(sortedUnique(profiles), policy.launch_settings.initially_disabled_profiles)) {
    throw new Error(`${domain} disabled profile set is not exact`);
  }
  validateEnvironmentSurface(domain, descriptor);
}

function normalizeTopology(text, files, descriptors, manifest, expectedReleaseSha) {
  assertNoPublicSecretMarkers(text, "CVM topology");
  const topology = exactKeys(parseJson(text, "CVM topology"), [
    "schema",
    "status",
    "release_sha",
    "source_ref",
    "generated_at",
    "deploymentIntentSha256",
    "deploymentIntent",
    "tinkerAccountBindingCeremonyReceipt",
    "image_manifest",
    "image_manifest_attestation",
    "trust_domains",
    "checks",
  ], "CVM topology");
  if (text !== canonicalSortedJsonText(topology)) {
    throw new Error("CVM topology is not canonical sorted two-space JSON");
  }
  if (!isRecord(topology)
    || topology.schema !== "dnai.cvm-topology.v6"
    || topology.status !== "rendered_not_deployed"
    || topology.release_sha !== expectedReleaseSha
    || topology.source_ref !== manifest.sourceRef
    || topology.generated_at !== manifest.generatedAt
    || !isRecord(topology.trust_domains)) {
    throw new Error("CVM topology release authority is invalid");
  }
  if (topology.image_manifest?.file !== "dnai-tee-image-release.json"
    || topology.image_manifest?.sha256 !== files.manifest.sha256
    || topology.image_manifest_attestation?.file !== "dnai-tee-image-release.bundle.json"
    || topology.image_manifest_attestation?.sha256 !== files.bundle.sha256
    || topology.deploymentIntent?.file !== "dnai-deployment-intent-core.json"
    || topology.deploymentIntent?.sha256 !== files.deploymentIntent.sha256
    || topology.deploymentIntentSha256 !== `sha256:${files.deploymentIntent.sha256}`) {
    throw new Error("CVM topology does not bind the exact companion release files");
  }
  const accountBindingReceipt = parseJson(
    files.accountBindingCeremonyReceipt.text,
    "Tinker account-binding ceremony receipt",
  );
  if (!isRecord(accountBindingReceipt)
    || files.accountBindingCeremonyReceipt.text
      !== canonicalSortedJsonText(accountBindingReceipt)
    || accountBindingReceipt.schema
      !== TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SCHEMA
    || !SHA256.test(
      accountBindingReceipt[
        TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD
      ],
    )
    || accountBindingReceipt[
      TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD
    ] === `sha256:${"0".repeat(64)}`) {
    throw new Error(
      "Tinker account-binding ceremony receipt companion is invalid",
    );
  }
  const accountBindingProjection = exactKeys(
    topology.tinkerAccountBindingCeremonyReceipt,
    [
      "file",
      "sha256",
      "schema",
      "tinkerAccountBindingCeremonyReceiptSha256",
      "validation",
    ],
    "CVM topology Tinker account-binding ceremony receipt",
  );
  if (accountBindingProjection.file
      !== TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME
    || accountBindingProjection.sha256
      !== files.accountBindingCeremonyReceipt.sha256
    || accountBindingProjection.schema
      !== TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SCHEMA
    || accountBindingProjection.tinkerAccountBindingCeremonyReceiptSha256
      !== accountBindingReceipt[
        TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD
      ]
    || accountBindingProjection.validation
      !== TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_TOPOLOGY_VALIDATION) {
    throw new Error(
      "CVM topology does not bind the exact Tinker account-binding ceremony receipt",
    );
  }
  if (!sameStringSet(Object.keys(topology.trust_domains), CVM_LAUNCH_DOMAINS)) {
    throw new Error("CVM topology does not contain the seven exact trust domains");
  }
  for (const domain of CVM_LAUNCH_DOMAINS) {
    const entry = topology.trust_domains[domain];
    const expectedImages = sortedUnique(
      CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain]
        .map((service) => manifest.byName[expectedServiceImageName(domain, service)].image),
    );
    if (!isRecord(entry)
      || entry.compose !== CVM_LAUNCH_DESCRIPTOR_FILES[domain]
      || entry.sha256 !== descriptors[domain].file.sha256
      || !sameStringSet(entry.services, CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain])
      || !sameStringSet(entry.images, expectedImages)) {
      throw new Error(`CVM topology does not bind the exact ${domain} descriptor`);
    }
  }
  const checks = topology.checks;
  const expectedChecks = {
    literal_digest_pins: true,
    linux_amd64_only: true,
    local_build_contexts: false,
    seven_cvm_descriptors: true,
    purpose_separated_qvl_descriptors: true,
    raw_secret_values_embedded: false,
    deployment_attempted: false,
    tdx_verification_claimed: false,
  };
  for (const [key, value] of Object.entries(expectedChecks)) {
    if (checks?.[key] !== value) throw new Error(`CVM topology check ${key} is not fail-closed`);
  }
  return topology;
}

async function exactReleaseDirectory(releaseDirectory) {
  const resolved = path.resolve(releaseDirectory || "");
  if (path.basename(resolved) !== CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY.generated_output_directory
    || await realpath(resolved) !== resolved) {
    throw new Error("generated descriptor directory must be one non-symlink .release directory");
  }
  return resolved;
}

export async function validateCanonicalGeneratedCvmDescriptorSet({
  releaseDirectory,
  expectedReleaseSha,
}) {
  const releaseSha = exactReleaseSha(expectedReleaseSha, "expected release SHA");
  const directory = await exactReleaseDirectory(releaseDirectory);
  const [
    manifestFile,
    bundleFile,
    deploymentIntentFile,
    accountBindingCeremonyReceiptFile,
  ] = await Promise.all([
    readStablePublicFile(path.join(directory, "dnai-tee-image-release.json"), "image release manifest"),
    readStablePublicFile(path.join(directory, "dnai-tee-image-release.bundle.json"), "image release attestation bundle"),
    readStablePublicFile(path.join(directory, "dnai-deployment-intent-core.json"), "deployment intent"),
    readStablePublicFile(
      path.join(
        directory,
        TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME,
      ),
      "Tinker account-binding ceremony receipt",
    ),
  ]);
  assertNoPublicSecretMarkers(bundleFile.text, "image release attestation bundle");
  assertNoPublicSecretMarkers(deploymentIntentFile.text, "deployment intent");
  assertNoPublicSecretMarkers(
    accountBindingCeremonyReceiptFile.text,
    "Tinker account-binding ceremony receipt",
  );
  const manifest = normalizeReleaseManifest(manifestFile.text, releaseSha);
  const descriptors = {};
  for (const domain of CVM_LAUNCH_DOMAINS) {
    const file = await readStablePublicFile(
      path.join(directory, CVM_LAUNCH_DESCRIPTOR_FILES[domain]),
      `${domain} descriptor`,
    );
    const document = parseGeneratedDescriptor(file.text, manifestFile.sha256, domain);
    validateDescriptorDocument(domain, document, manifest, releaseSha);
    descriptors[domain] = Object.freeze({ file, document });
  }
  const descriptorHashes = CVM_LAUNCH_DOMAINS.map((domain) => descriptors[domain].file.sha256);
  if (new Set(descriptorHashes).size !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("the seven raw descriptor hashes must be pairwise distinct");
  }
  const topologyFile = await readStablePublicFile(
    path.join(directory, "dnai-cvm-topology.json"),
    "CVM topology",
  );
  const topology = normalizeTopology(
    topologyFile.text,
    {
      manifest: manifestFile,
      bundle: bundleFile,
      deploymentIntent: deploymentIntentFile,
      accountBindingCeremonyReceipt: accountBindingCeremonyReceiptFile,
    },
    descriptors,
    manifest,
    releaseSha,
  );
  return Object.freeze({
    schema: CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
    status: "validated_rendered_not_deployed",
    truth_status: "descriptor_consistency_not_cvm_creation_tdx_or_runtime_evidence",
    materialization_boundary: CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
    release_sha: releaseSha,
    source_ref: manifest.sourceRef,
    image_manifest_sha256: `sha256:${manifestFile.sha256}`,
    image_manifest_sigstore_bundle_sha256: `sha256:${bundleFile.sha256}`,
    topology_sha256: `sha256:${topologyFile.sha256}`,
    tinker_account_binding_ceremony_receipt_sha256:
      topology.tinkerAccountBindingCeremonyReceipt
        .tinkerAccountBindingCeremonyReceiptSha256,
    descriptor_sha256_by_domain: Object.freeze(Object.fromEntries(
      CVM_LAUNCH_DOMAINS.map((domain) => [domain, `sha256:${descriptors[domain].file.sha256}`]),
    )),
    service_matrix: CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
    image_references: Object.freeze(manifest.images.map((image) => image.image)),
    invariants: Object.freeze({
      all_seven_generated_files_present: true,
      exact_raw_hashes_bound_by_topology: true,
      exact_service_matrices: true,
      exact_clean_ci_image_digests: true,
      embedded_secret_values: false,
      deployment_claimed: false,
      tdx_attestation_claimed: false,
    }),
  });
}

async function defaultGitRunner(args, { cwd }) {
  const result = await execFileAsync("git", args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  return result.stdout;
}

async function defaultRendererRunner({ repositoryRoot, outputDirectory, releaseDirectory, releaseSha }) {
  const projectRoot = path.join(repositoryRoot, "⚙️", "tinker-delegate");
  try {
    await execFileAsync("uv", [
      "run",
      "--frozen",
      "tinker-release-composes",
      "--manifest",
      path.join(releaseDirectory, "dnai-tee-image-release.json"),
      "--manifest-attestation-bundle",
      path.join(releaseDirectory, "dnai-tee-image-release.bundle.json"),
      "--deployment-intent",
      path.join(releaseDirectory, "dnai-deployment-intent-core.json"),
      "--account-binding-ceremony-receipt",
      path.join(
        releaseDirectory,
        TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME,
      ),
      "--release-sha",
      releaseSha,
      "--output-dir",
      outputDirectory,
    ], {
      cwd: projectRoot,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    });
  } catch {
    throw new Error("exact tracked-source descriptor reproduction failed");
  }
}

export async function verifyExactTrackedSourceDescriptorReproduction({
  repositoryRoot,
  releaseDirectory,
  expectedReleaseSha,
  rendererRunner = defaultRendererRunner,
}) {
  const releaseSha = exactReleaseSha(expectedReleaseSha, "expected release SHA");
  const root = path.resolve(repositoryRoot || "");
  if (await realpath(root) !== root) throw new Error("repository root must not contain symbolic links");
  const directory = await exactReleaseDirectory(releaseDirectory);
  if (directory !== path.join(root, ".release")) {
    throw new Error("generated descriptor directory must be the repository's exact .release directory");
  }
  if (directory !== path.join(root, CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY.generated_output_directory)) {
    throw new Error("generated descriptor directory must be the repository's exact .release path");
  }
  await validateCanonicalGeneratedCvmDescriptorSet({
    releaseDirectory: directory,
    expectedReleaseSha: releaseSha,
  });
  const temporaryRoot = await realpath(await mkdtemp(path.join(os.tmpdir(), "dnai-cvm-rerender-")));
  const outputDirectory = path.join(temporaryRoot, ".release");
  try {
    await mkdir(outputDirectory, { mode: 0o700 });
    await rendererRunner({
      repositoryRoot: root,
      outputDirectory,
      releaseDirectory: directory,
      releaseSha,
    });
    const reproducedSha256ByFile = {};
    for (const filename of CVM_RELEASE_DESCRIPTOR_GENERATED_FILES) {
      const [reviewed, reproduced] = await Promise.all([
        readStablePublicFile(path.join(directory, filename), `reviewed generated file ${filename}`),
        readStablePublicFile(path.join(outputDirectory, filename), `reproduced generated file ${filename}`),
      ]);
      if (!reviewed.bytes.equals(reproduced.bytes)) {
        throw new Error(`generated release file ${filename} is not the exact tracked-source reproduction`);
      }
      reproducedSha256ByFile[filename] = `sha256:${reproduced.sha256}`;
    }
    return Object.freeze({
      schema: "dnai.cvm-release-descriptor-reproduction.v1",
      status: "exact_tracked_source_reproduction",
      release_sha: releaseSha,
      generated_file_count: CVM_RELEASE_DESCRIPTOR_GENERATED_FILES.length,
      generated_file_sha256: Object.freeze(reproducedSha256ByFile),
      deployment_attempted: false,
      tdx_attestation_claimed: false,
    });
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

export async function inspectTrackedDescriptorMaterializationSources({
  repositoryRoot,
  expectedReleaseSha,
  gitRunner = defaultGitRunner,
}) {
  const releaseSha = exactReleaseSha(expectedReleaseSha, "expected release SHA");
  const root = path.resolve(repositoryRoot || "");
  if (await realpath(root) !== root) throw new Error("repository root must not contain symbolic links");
  const sourceFiles = [];
  for (const relative of CVM_RELEASE_DESCRIPTOR_TRACKED_SOURCE_FILES) {
    const file = await readStablePublicFile(path.join(root, relative), `tracked descriptor source ${relative}`);
    sourceFiles.push(Object.freeze({ path: relative, sha256: `sha256:${file.sha256}` }));
  }
  const blockers = [];
  let head = "";
  try {
    head = String(await gitRunner(["rev-parse", "--verify", "HEAD"], { cwd: root })).trim().toLowerCase();
  } catch {
    blockers.push("git_head_unavailable");
  }
  if (head !== releaseSha) blockers.push("git_head_does_not_equal_release_sha");
  try {
    await gitRunner([
      "ls-files",
      "--error-unmatch",
      "--",
      ...CVM_RELEASE_DESCRIPTOR_TRACKED_SOURCE_FILES,
    ], { cwd: root });
  } catch {
    blockers.push("descriptor_materialization_source_untracked");
  }
  try {
    const status = String(await gitRunner([
      "status",
      "--porcelain=v1",
      "--untracked-files=all",
      "--",
      ...CVM_RELEASE_DESCRIPTOR_TRACKED_SOURCE_FILES,
    ], { cwd: root })).trim();
    if (status) blockers.push("descriptor_materialization_source_dirty");
  } catch {
    blockers.push("descriptor_materialization_source_status_unavailable");
  }
  return Object.freeze({
    schema: "dnai.cvm-release-descriptor-source-inspection.v1",
    ready: blockers.length === 0,
    release_sha: releaseSha,
    git_head: RELEASE_SHA.test(head) ? head : null,
    boundary: CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
    source_files: Object.freeze(sourceFiles),
    blockers: Object.freeze(blockers),
  });
}

export async function assertTrackedDescriptorMaterializationSources(input) {
  const receipt = await inspectTrackedDescriptorMaterializationSources(input);
  if (!receipt.ready) {
    throw new Error(`tracked descriptor materialization sources are not release-ready: ${receipt.blockers.join(",")}`);
  }
  return receipt;
}

function parseCli(argv) {
  const [command, ...rest] = argv;
  if (command === "--help" || command === "-h") return { command: "help" };
  if (command !== "check") throw new Error("supported command is check");
  const allowed = new Set(["--repo-root", "--release-dir", "--release-sha"]);
  const values = { command };
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
    if (!allowed.has(flag) || Object.hasOwn(values, flag) || !value || value.startsWith("--")) {
      throw new Error("check requires exact unique --repo-root, --release-dir, and --release-sha arguments");
    }
    values[flag] = value;
  }
  if ([...allowed].some((flag) => !Object.hasOwn(values, flag))
    || Object.keys(values).length !== allowed.size + 1) {
    throw new Error("check requires exact unique --repo-root, --release-dir, and --release-sha arguments");
  }
  return values;
}

export async function main(argv = process.argv.slice(2), io = console) {
  try {
    const args = parseCli(argv);
    if (args.command === "help") {
      io.log("Usage: node scripts/cvm-release-descriptor-set-v3.mjs check --repo-root DIR --release-dir DIR/.release --release-sha 40_HEX");
      return 0;
    }
    const sourceReceipt = await assertTrackedDescriptorMaterializationSources({
      repositoryRoot: args["--repo-root"],
      expectedReleaseSha: args["--release-sha"],
    });
    const descriptorReceipt = await validateCanonicalGeneratedCvmDescriptorSet({
      releaseDirectory: args["--release-dir"],
      expectedReleaseSha: args["--release-sha"],
    });
    const reproductionReceipt = await verifyExactTrackedSourceDescriptorReproduction({
      repositoryRoot: args["--repo-root"],
      releaseDirectory: args["--release-dir"],
      expectedReleaseSha: args["--release-sha"],
    });
    io.log(JSON.stringify({
      source: sourceReceipt,
      descriptors: descriptorReceipt,
      reproduction: reproductionReceipt,
    }));
    return 0;
  } catch (error) {
    io.error(JSON.stringify({
      schema: "dnai.cvm-release-descriptor-set-error.v1",
      status: "blocked",
      message: error instanceof Error ? error.message : "descriptor validation failed",
      deployment_attempted: false,
    }));
    return 2;
  }
}

if (process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(new URL(
    "./cvm-release-descriptor-set-v3.mjs",
    import.meta.url,
  ))) {
  process.exitCode = await main();
}
