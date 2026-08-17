#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { open, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  parseCanonicalPublicHttpsUrl,
} from "./canonical-public-https-url-core.mjs";

export const BUILD_DESCRIPTOR_SCHEMA = "dnai.tee-image-build.v1";
export const RELEASE_SCHEMA = "dnai.tee-image-release.v1";
export const PLATFORM = "linux/amd64";
export const IMAGE_NAMES = Object.freeze([
  "tinker-delegate",
  "tee-email-oracle",
  "neko-chrome",
  "attestation-qvl",
  "compute-metering",
]);

const PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1";
const SBOM_PREDICATE = "https://spdx.dev/Document/v2.3";
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RELEASE_SHA = /^[0-9a-f]{40}$/;
const SAFE_REF = /^refs\/(?:heads\/[0-9A-Za-z._/-]+|tags\/v[0-9][0-9A-Za-z._-]*)$/;
const RELEASE_REF = /^(?:refs\/heads\/main|refs\/tags\/v[0-9][0-9A-Za-z._-]*)$/;
const REPOSITORY = /^[0-9a-z](?:[0-9a-z._-]{0,98}[0-9a-z])?\/[0-9a-z](?:[0-9a-z._-]{0,98}[0-9a-z])?$/;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.join("\0") !== expected.join("\0")) {
    const missing = expected.filter((key) => !actual.includes(key));
    const extra = actual.filter((key) => !expected.includes(key));
    throw new Error(`${label} fields are not exact: missing ${missing.join(",") || "none"}; extra ${extra.join(",") || "none"}`);
  }
  return value;
}

function boundedString(value, label, maxLength = 512) {
  if (typeof value !== "string" || value.length < 1 || value.length > maxLength || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${label} must be a non-empty bounded string without control characters`);
  }
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function safeHttpsUrl(value, label) {
  const raw = boundedString(value, label, 1024);
  parseCanonicalPublicHttpsUrl(raw, { label, maximumBytes: 1024 });
  return raw;
}

function normalizeDigest(value, label = "digest") {
  const digest = boundedString(value, label, 96).toLowerCase();
  if (!SHA256.test(digest)) throw new Error(`${label} must be a lowercase sha256 digest`);
  return digest;
}

function normalizeReleaseSha(value, label = "release SHA") {
  const releaseSha = boundedString(value, label, 64).toLowerCase();
  if (!RELEASE_SHA.test(releaseSha)) throw new Error(`${label} must be 40 lowercase hex characters`);
  return releaseSha;
}

function normalizeSourceRepository(value) {
  const repository = boundedString(value, "source repository", 200).toLowerCase();
  if (!REPOSITORY.test(repository)) throw new Error("source repository must be a lowercase owner/name pair");
  return repository;
}

function normalizeSourceRef(value, { releaseOnly = false } = {}) {
  const sourceRef = boundedString(value, "source ref", 300);
  const pattern = releaseOnly ? RELEASE_REF : SAFE_REF;
  if (!pattern.test(sourceRef) || sourceRef.includes("..") || sourceRef.includes("//")) {
    throw new Error(releaseOnly
      ? "source ref must be refs/heads/main or a v-prefixed release tag"
      : "source ref is not a safe branch or v-prefixed tag ref");
  }
  return sourceRef;
}

function normalizeTimestamp(value) {
  const timestamp = boundedString(value, "generated_at", 64);
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== timestamp) {
    throw new Error("generated_at must be a canonical UTC ISO-8601 timestamp");
  }
  return timestamp;
}

function normalizeWorkflowRunId(value) {
  const runId = boundedString(value, "workflow run id", 32);
  if (!/^[1-9][0-9]*$/.test(runId)) throw new Error("workflow run id must be a positive integer string");
  return runId;
}

function normalizeAttestation(value, label, predicateType) {
  const parsed = exactRecord(value, ["predicate_type", "id", "url"], label);
  if (parsed.predicate_type !== predicateType) throw new Error(`${label} predicate type mismatch`);
  const id = boundedString(parsed.id, `${label}.id`, 128);
  if (!/^[1-9][0-9]*$/.test(id)) throw new Error(`${label}.id must be a positive integer string`);
  return {
    predicate_type: predicateType,
    id,
    url: safeHttpsUrl(parsed.url, `${label}.url`),
  };
}

function normalizeSbomArtifact(value, name) {
  const parsed = exactRecord(value, ["filename", "sha256"], "sbom_artifact");
  const filename = boundedString(parsed.filename, "sbom_artifact.filename", 160);
  if (filename !== `${name}.spdx.json`) throw new Error(`SBOM filename must be ${name}.spdx.json`);
  if (!/^[0-9a-f]{64}$/.test(parsed.sha256)) throw new Error("SBOM sha256 must be 64 lowercase hex characters");
  return { filename, sha256: parsed.sha256 };
}

function normalizeVerification(value, expected) {
  const parsed = exactRecord(value, [
    "image",
    "repo",
    "signer_workflow",
    "source_digest",
    "source_ref",
    "provenance_attestation",
    "sbom_attestation",
    "raw_secret_egress",
  ], `verification for ${expected.name}`);
  if (
    parsed.image !== expected.image
    || parsed.repo.toLowerCase() !== expected.sourceRepository
    || parsed.signer_workflow.toLowerCase() !== expected.signerWorkflow
    || parsed.source_digest.toLowerCase() !== expected.releaseSha
    || parsed.source_ref !== expected.sourceRef
  ) {
    throw new Error(`verification identity mismatch for ${expected.name}`);
  }
  if (parsed.provenance_attestation !== "verified" || parsed.sbom_attestation !== "verified") {
    throw new Error(`both GitHub attestations must be verified for ${expected.name}`);
  }
  if (parsed.raw_secret_egress !== false) throw new Error(`verification for ${expected.name} must prohibit raw secret egress`);
  return {
    repo: expected.sourceRepository,
    signer_workflow: expected.signerWorkflow,
    source_digest: expected.releaseSha,
    source_ref: expected.sourceRef,
    provenance_attestation: "verified",
    sbom_attestation: "verified",
  };
}

export function normalizeBuildDescriptor(value) {
  const descriptor = exactRecord(value, [
    "schema",
    "release_sha",
    "source_ref",
    "source_repository",
    "signer_workflow",
    "image",
  ], "image build descriptor");
  if (descriptor.schema !== BUILD_DESCRIPTOR_SCHEMA) throw new Error(`image build descriptor schema must be ${BUILD_DESCRIPTOR_SCHEMA}`);
  const releaseSha = normalizeReleaseSha(descriptor.release_sha);
  const sourceRef = normalizeSourceRef(descriptor.source_ref);
  const sourceRepository = normalizeSourceRepository(descriptor.source_repository);
  const signerWorkflow = boundedString(descriptor.signer_workflow, "signer workflow", 320).toLowerCase();
  if (signerWorkflow !== `${sourceRepository}/.github/workflows/build-tee-images.yml`) {
    throw new Error("signer workflow does not match the source repository TEE image workflow");
  }

  const image = exactRecord(descriptor.image, [
    "name",
    "repository",
    "digest",
    "image",
    "platform",
    "sbom_artifact",
    "provenance_subject",
    "attestations",
  ], "image build descriptor image");
  const name = boundedString(image.name, "image name", 64);
  if (!IMAGE_NAMES.includes(name)) throw new Error(`unsupported production image name: ${name}`);
  const repository = boundedString(image.repository, "image repository", 400).toLowerCase();
  const expectedRepository = `ghcr.io/${sourceRepository}/${name}`;
  if (repository !== expectedRepository) throw new Error(`image repository must be ${expectedRepository}`);
  const digest = normalizeDigest(image.digest);
  if (image.image !== `${repository}@${digest}`) throw new Error("digest-pinned image reference mismatch");
  if (image.platform !== PLATFORM) throw new Error(`image platform must be ${PLATFORM}`);

  const subject = exactRecord(image.provenance_subject, ["name", "digest"], "provenance_subject");
  if (subject.name !== repository || subject.digest !== digest) throw new Error("provenance subject must exactly match the image repository and digest");
  const attestations = exactRecord(image.attestations, ["provenance", "sbom"], "attestations");

  return {
    schema: BUILD_DESCRIPTOR_SCHEMA,
    release_sha: releaseSha,
    source_ref: sourceRef,
    source_repository: sourceRepository,
    signer_workflow: signerWorkflow,
    image: {
      name,
      repository,
      digest,
      image: `${repository}@${digest}`,
      platform: PLATFORM,
      sbom_artifact: normalizeSbomArtifact(image.sbom_artifact, name),
      provenance_subject: { name: repository, digest },
      attestations: {
        provenance: normalizeAttestation(attestations.provenance, "provenance attestation", PROVENANCE_PREDICATE),
        sbom: normalizeAttestation(attestations.sbom, "SBOM attestation", SBOM_PREDICATE),
      },
    },
  };
}

export async function createBuildDescriptor(input) {
  const name = boundedString(input.name, "image name", 64);
  if (!IMAGE_NAMES.includes(name)) throw new Error(`unsupported production image name: ${name}`);
  const sbomPath = path.resolve(boundedString(input.sbomPath, "SBOM path", 4096));
  const sbomBytes = await readFile(sbomPath);
  if (sbomBytes.length < 2 || sbomBytes.length > 32 * 1024 * 1024) {
    throw new Error("SPDX SBOM must be between 2 bytes and 32 MiB");
  }
  let sbom;
  try {
    sbom = JSON.parse(sbomBytes.toString("utf8"));
  } catch {
    throw new Error("SPDX SBOM is not valid JSON");
  }
  if (!isRecord(sbom) || sbom.spdxVersion !== "SPDX-2.3" || sbom.SPDXID !== "SPDXRef-DOCUMENT") {
    throw new Error("SBOM must be an SPDX 2.3 JSON document");
  }

  const sourceRepository = normalizeSourceRepository(input.sourceRepository);
  const repository = boundedString(input.repository, "image repository", 400).toLowerCase();
  const digest = normalizeDigest(input.digest);
  return normalizeBuildDescriptor({
    schema: BUILD_DESCRIPTOR_SCHEMA,
    release_sha: normalizeReleaseSha(input.releaseSha),
    source_ref: normalizeSourceRef(input.sourceRef),
    source_repository: sourceRepository,
    signer_workflow: boundedString(input.signerWorkflow, "signer workflow", 320).toLowerCase(),
    image: {
      name,
      repository,
      digest,
      image: `${repository}@${digest}`,
      platform: input.platform,
      sbom_artifact: {
        filename: `${name}.spdx.json`,
        sha256: sha256(sbomBytes),
      },
      provenance_subject: { name: repository, digest },
      attestations: {
        provenance: {
          predicate_type: PROVENANCE_PREDICATE,
          id: input.provenanceId,
          url: input.provenanceUrl,
        },
        sbom: {
          predicate_type: SBOM_PREDICATE,
          id: input.sbomId,
          url: input.sbomUrl,
        },
      },
    },
  });
}

async function readJson(filePath, label) {
  const raw = await readFile(filePath);
  if (raw.length < 2 || raw.length > 4 * 1024 * 1024) throw new Error(`${label} is outside the 4 MiB input limit`);
  try {
    return JSON.parse(raw.toString("utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

async function jsonFiles(directory, label) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = entries.filter((entry) => entry.isFile() && entry.name.endsWith(".json"));
  if (files.length !== IMAGE_NAMES.length) throw new Error(`${label} must contain exactly ${IMAGE_NAMES.length} JSON files`);
  return files.map((entry) => path.join(directory, entry.name)).sort();
}

async function readBoundedRegularFile(filePath, label, maximum) {
  let handle;
  try {
    handle = await open(
      filePath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
    );
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size < 2n || before.size > BigInt(maximum)) {
      throw new Error(`${label} must be a regular file between 2 bytes and ${maximum} bytes`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const stable = ["dev", "ino", "size", "mtimeNs", "ctimeNs"]
      .every((field) => before[field] === after[field]);
    if (
      BigInt(bytes.length) !== before.size
      || !stable
    ) {
      throw new Error(`${label} changed during the bounded read`);
    }
    return bytes;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(`${label} `)) throw error;
    throw new Error(`${label} must be a readable no-follow regular file`);
  } finally {
    await handle?.close();
  }
}

async function validateDownloadedSboms(directory, descriptors) {
  const resolved = path.resolve(directory);
  const entries = await readdir(resolved, { withFileTypes: true });
  const expectedNames = IMAGE_NAMES.map((name) => `${name}.spdx.json`).sort();
  const actualNames = entries.map((entry) => entry.name).sort();
  if (
    entries.length !== IMAGE_NAMES.length
    || entries.some((entry) => !entry.isFile())
    || actualNames.join("\0") !== expectedNames.join("\0")
  ) {
    throw new Error("SBOM directory must contain exactly the five canonical regular SPDX JSON files");
  }

  for (const descriptor of descriptors) {
    const filename = `${descriptor.image.name}.spdx.json`;
    const bytes = await readBoundedRegularFile(
      path.join(resolved, filename),
      `downloaded SBOM ${filename}`,
      32 * 1024 * 1024,
    );
    let sbom;
    try {
      sbom = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new Error(`downloaded SBOM ${filename} is not valid JSON`);
    }
    if (!isRecord(sbom) || sbom.spdxVersion !== "SPDX-2.3" || sbom.SPDXID !== "SPDXRef-DOCUMENT") {
      throw new Error(`downloaded SBOM ${filename} must be an SPDX 2.3 JSON document`);
    }
    if (sha256(bytes) !== descriptor.image.sbom_artifact.sha256) {
      throw new Error(`downloaded SBOM sha256 mismatch for ${descriptor.image.name}`);
    }
  }
}

async function loadBuildDescriptors(directory) {
  const descriptorPaths = await jsonFiles(path.resolve(directory), "descriptor directory");
  const descriptors = await Promise.all(descriptorPaths.map(async (filePath) => normalizeBuildDescriptor(await readJson(filePath, "image build descriptor"))));
  const names = new Set(descriptors.map((descriptor) => descriptor.image.name));
  if (names.size !== IMAGE_NAMES.length || IMAGE_NAMES.some((name) => !names.has(name))) {
    throw new Error("image descriptors must contain every required production image exactly once");
  }
  const first = descriptors[0];
  const releaseSha = first.release_sha;
  const sourceRef = normalizeSourceRef(first.source_ref, { releaseOnly: true });
  const sourceRepository = first.source_repository;
  const signerWorkflow = first.signer_workflow;
  for (const descriptor of descriptors) {
    if (
      descriptor.release_sha !== releaseSha
      || descriptor.source_ref !== sourceRef
      || descriptor.source_repository !== sourceRepository
      || descriptor.signer_workflow !== signerWorkflow
    ) {
      throw new Error("all image descriptors must come from the same source commit, ref, repository, and workflow");
    }
  }
  return { descriptors, releaseSha, sourceRef, sourceRepository, signerWorkflow };
}

export async function createVerificationPlan(descriptorsDirectory) {
  const { descriptors, releaseSha, sourceRef, sourceRepository, signerWorkflow } = await loadBuildDescriptors(descriptorsDirectory);
  return IMAGE_NAMES.map((name) => {
    const descriptor = descriptors.find((candidate) => candidate.image.name === name);
    return {
      name,
      image: descriptor.image.image,
      repo: sourceRepository,
      signer_workflow: signerWorkflow,
      source_digest: releaseSha,
      source_ref: sourceRef,
    };
  });
}

export async function createReleaseManifest({ descriptorsDirectory, verificationsDirectory, sbomsDirectory, generatedAt, workflowRunId, workflowRunUrl }) {
  const { descriptors, releaseSha, sourceRef, sourceRepository, signerWorkflow } = await loadBuildDescriptors(descriptorsDirectory);
  await validateDownloadedSboms(sbomsDirectory, descriptors);
  const verificationPaths = await jsonFiles(path.resolve(verificationsDirectory), "verification directory");

  const verificationValues = await Promise.all(verificationPaths.map((filePath) => readJson(filePath, "image verification")));
  const verificationByImage = new Map();
  for (const value of verificationValues) {
    if (!isRecord(value) || typeof value.image !== "string" || verificationByImage.has(value.image)) {
      throw new Error("image verifications must contain unique image references");
    }
    verificationByImage.set(value.image, value);
  }

  const images = IMAGE_NAMES.map((name) => {
    const descriptor = descriptors.find((candidate) => candidate.image.name === name);
    const verificationValue = verificationByImage.get(descriptor.image.image);
    if (!verificationValue) throw new Error(`missing exact GitHub verification for ${name}`);
    return {
      ...descriptor.image,
      verification: normalizeVerification(verificationValue, {
        name,
        image: descriptor.image.image,
        sourceRepository,
        signerWorkflow,
        releaseSha,
        sourceRef,
      }),
    };
  });

  return {
    schema: RELEASE_SCHEMA,
    release_sha: releaseSha,
    source_ref: sourceRef,
    generated_at: normalizeTimestamp(generatedAt),
    source_repository: sourceRepository,
    signer_workflow: signerWorkflow,
    workflow_run_id: normalizeWorkflowRunId(workflowRunId),
    workflow_run_url: safeHttpsUrl(workflowRunUrl, "workflow run URL"),
    platform: PLATFORM,
    images,
  };
}

function parseFlags(argv, allowed) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!flag.startsWith("--") || !allowed.has(flag)) throw new Error(`unknown argument: ${flag}`);
    if (Object.hasOwn(result, flag)) throw new Error(`duplicate argument: ${flag}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${flag}`);
    result[flag] = value;
    index += 1;
  }
  for (const flag of allowed) {
    if (!Object.hasOwn(result, flag)) throw new Error(`${flag} is required`);
  }
  return result;
}

async function atomicWriteJson(output, value) {
  const target = path.resolve(output);
  const temporary = `${target}.tmp-${process.pid}`;
  await rm(temporary, { force: true });
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o644 });
    await rename(temporary, target);
  } finally {
    await rm(temporary, { force: true });
  }
}

function usage() {
  console.error([
    "Usage:",
    "  node scripts/build-tee-image-release.mjs descriptor [all descriptor flags]",
    "  node scripts/build-tee-image-release.mjs verification-plan --descriptors DIRECTORY",
    "  node scripts/build-tee-image-release.mjs aggregate [all aggregate flags]",
  ].join("\n"));
}

export async function main(argv = process.argv.slice(2)) {
  const [command, ...rest] = argv;
  if (command === "descriptor") {
    const flags = parseFlags(rest, new Set([
      "--name", "--repository", "--digest", "--platform", "--source-repository", "--release-sha",
      "--source-ref", "--signer-workflow", "--provenance-id", "--provenance-url", "--sbom-id",
      "--sbom-url", "--sbom-file", "--output",
    ]));
    const descriptor = await createBuildDescriptor({
      name: flags["--name"],
      repository: flags["--repository"],
      digest: flags["--digest"],
      platform: flags["--platform"],
      sourceRepository: flags["--source-repository"],
      releaseSha: flags["--release-sha"],
      sourceRef: flags["--source-ref"],
      signerWorkflow: flags["--signer-workflow"],
      provenanceId: flags["--provenance-id"],
      provenanceUrl: flags["--provenance-url"],
      sbomId: flags["--sbom-id"],
      sbomUrl: flags["--sbom-url"],
      sbomPath: flags["--sbom-file"],
    });
    await atomicWriteJson(flags["--output"], descriptor);
    return;
  }
  if (command === "aggregate") {
    const flags = parseFlags(rest, new Set([
      "--descriptors", "--verifications", "--sboms", "--generated-at", "--workflow-run-id", "--workflow-run-url", "--output",
    ]));
    const manifest = await createReleaseManifest({
      descriptorsDirectory: flags["--descriptors"],
      verificationsDirectory: flags["--verifications"],
      sbomsDirectory: flags["--sboms"],
      generatedAt: flags["--generated-at"],
      workflowRunId: flags["--workflow-run-id"],
      workflowRunUrl: flags["--workflow-run-url"],
    });
    await atomicWriteJson(flags["--output"], manifest);
    return;
  }
  if (command === "verification-plan") {
    const flags = parseFlags(rest, new Set(["--descriptors"]));
    const plan = await createVerificationPlan(flags["--descriptors"]);
    for (const entry of plan) {
      console.log([
        entry.name,
        entry.image,
        entry.repo,
        entry.signer_workflow,
        entry.source_digest,
        entry.source_ref,
      ].join("\t"));
    }
    return;
  }
  usage();
  throw new Error("command must be descriptor or aggregate");
}

if (process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(new URL(
    "./build-tee-image-release.mjs",
    import.meta.url,
  ))) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
