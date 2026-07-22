import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";

export const RELEASE_MANIFEST_SIGSTORE_VERIFICATION_SCHEMA =
  "dnai.tee-image-release-manifest-sigstore-verification.v1";
export const RELEASE_MANIFEST_SIGSTORE_BLOCKER =
  "release_manifest_sigstore_bundle_not_cryptographically_verified";
export const RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_DOMAIN =
  "dnai-wikigen/tee-image-release-manifest-sigstore-verification/v1\0";

export const RELEASE_MANIFEST_SIGSTORE_AUTHORITY = Object.freeze({
  repository: "therealwiki/dnai-wikigen",
  source_ref: "refs/heads/main",
  signer_workflow:
    "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
  predicate_type: "https://slsa.dev/provenance/v1",
  subject_filename: "dnai-tee-image-release.json",
  bundle_filename: "dnai-tee-image-release.bundle.json",
});

export const PINNED_GH_TOOL = Object.freeze({
  path: "/opt/homebrew/Cellar/gh/2.87.3/bin/gh",
  version: "2.87.3",
  sha256:
    "sha256:67b51ba8ca861e0fcd4749d47eba740e8db8c799a8b18645833e904e09f7fb70",
});

export const GH_VERSION_TIMEOUT_MS = 5_000;
export const GH_ATTESTATION_TIMEOUT_MS = 30_000;
export const MAX_GH_VERSION_OUTPUT_BYTES = 4 * 1024;
export const MAX_GH_ATTESTATION_OUTPUT_BYTES = 1024 * 1024;
export const MAX_RELEASE_MANIFEST_BYTES = 2 * 1024 * 1024;
export const MAX_RELEASE_BUNDLE_BYTES = 8 * 1024 * 1024;
export const MAX_GH_EXECUTABLE_BYTES = 64 * 1024 * 1024;

const RELEASE_SCHEMA = "dnai.tee-image-release.v1";
const RELEASE_PLATFORM = "linux/amd64";
const IMAGE_NAMES = Object.freeze([
  "tinker-delegate",
  "tee-email-oracle",
  "neko-chrome",
  "attestation-qvl",
  "compute-metering",
]);
const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const SIGSTORE_BUNDLE_MEDIA_TYPE =
  /^application\/vnd\.dev\.sigstore\.bundle\.v0\.(?:2|3)\+json$/;
const SLSA_STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_HOSTED_RUNNER = "github-hosted";
const MAX_PATH_BYTES = 4_096;

const TOP_LEVEL_MANIFEST_KEYS = Object.freeze([
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
]);

const PRODUCTION_RECEIPT_KEYS = Object.freeze([
  "schema",
  "status",
  "blocker_code",
  "blocker_status",
  "release_sha",
  "release_manifest_sha256",
  "release_manifest_sigstore_bundle_sha256",
  "gh_executable_sha256",
  "gh_executable_path_sha256",
  "gh_version_output_sha256",
  "verification_command_sha256",
  "verification_output_sha256",
  "verified_identity_sha256",
]);

const IMAGE_KEYS = Object.freeze([
  "name",
  "repository",
  "digest",
  "image",
  "platform",
  "sbom_artifact",
  "provenance_subject",
  "attestations",
  "verification",
]);

const MINIMAL_GH_ENVIRONMENT = Object.freeze({
  PATH: "/usr/bin:/bin",
  HOME: "/var/empty",
  TMPDIR: "/var/empty",
  XDG_CONFIG_HOME: "/var/empty",
  LANG: "C",
  LC_ALL: "C",
  NO_COLOR: "1",
  CLICOLOR: "0",
  GH_PAGER: "cat",
  PAGER: "cat",
  GH_PROMPT_DISABLED: "1",
  GH_NO_UPDATE_NOTIFIER: "1",
});

export class ReleaseManifestSigstoreVerificationError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseManifestSigstoreVerificationError";
    this.code = code;
  }
}

function reject(code) {
  throw new ReleaseManifestSigstoreVerificationError(code);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expectedKeys, code) {
  if (!isRecord(value)) reject(code);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    reject(code);
  }
  return value;
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function domainSha256(domain, value) {
  const domainBytes = Buffer.from(`${domain}\0`, "utf8");
  const valueBytes = Buffer.isBuffer(value)
    ? value
    : Buffer.from(value, "utf8");
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(valueBytes.length));
  return sha256(Buffer.concat([domainBytes, length, valueBytes]));
}

function canonicalCompactJson(value) {
  return `${JSON.stringify(value)}\n`;
}

function expectedVerifiedIdentitySha256(releaseSha, manifestSha256) {
  return domainSha256(
    "dnai.tee-image-release-manifest-sigstore-identity.v1",
    canonicalCompactJson({
      repository: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.repository,
      signer_workflow:
        RELEASE_MANIFEST_SIGSTORE_AUTHORITY.signer_workflow,
      source_digest: releaseSha,
      source_ref: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.source_ref,
      subject_name:
        RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
      subject_sha256: manifestSha256,
    }),
  );
}

export const RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY =
  Object.freeze({
    schema: RELEASE_MANIFEST_SIGSTORE_VERIFICATION_SCHEMA,
    status: "verified_by_pinned_gh_sigstore",
    blocker_code: RELEASE_MANIFEST_SIGSTORE_BLOCKER,
    blocker_status: "cleared_by_this_receipt",
    gh_executable_sha256: PINNED_GH_TOOL.sha256,
    gh_executable_path_sha256: domainSha256(
      "dnai.pinned-gh-executable-path.v1",
      PINNED_GH_TOOL.path,
    ),
    gh_version_output_sha256:
      "sha256:b854454a206472d98565ff7c406ff085b3df45b833044782c099302a09c280d9",
  });

export function normalizeReleaseManifestSigstoreVerificationReceipt(value) {
  const parsed = exactKeys(
    value,
    PRODUCTION_RECEIPT_KEYS,
    "release_manifest_sigstore_receipt_fields_invalid",
  );
  const authority = RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY;
  if (
    parsed.schema !== authority.schema
    || parsed.status !== authority.status
    || parsed.blocker_code !== authority.blocker_code
    || parsed.blocker_status !== authority.blocker_status
    || parsed.gh_executable_sha256 !== authority.gh_executable_sha256
    || parsed.gh_executable_path_sha256
      !== authority.gh_executable_path_sha256
    || parsed.gh_version_output_sha256
      !== authority.gh_version_output_sha256
  ) {
    reject("release_manifest_sigstore_receipt_authority_invalid");
  }
  const releaseSha = normalizeReleaseSha(parsed.release_sha);
  for (const field of [
    "release_manifest_sha256",
    "release_manifest_sigstore_bundle_sha256",
    "verification_command_sha256",
    "verification_output_sha256",
    "verified_identity_sha256",
  ]) {
    if (typeof parsed[field] !== "string" || !SHA256.test(parsed[field])) {
      reject("release_manifest_sigstore_receipt_digest_invalid");
    }
  }
  if (
    parsed.verified_identity_sha256
      !== expectedVerifiedIdentitySha256(
        releaseSha,
        parsed.release_manifest_sha256,
      )
  ) {
    reject("release_manifest_sigstore_receipt_identity_invalid");
  }
  return Object.freeze({
    schema: authority.schema,
    status: authority.status,
    blocker_code: authority.blocker_code,
    blocker_status: authority.blocker_status,
    release_sha: releaseSha,
    release_manifest_sha256: parsed.release_manifest_sha256,
    release_manifest_sigstore_bundle_sha256:
      parsed.release_manifest_sigstore_bundle_sha256,
    gh_executable_sha256: authority.gh_executable_sha256,
    gh_executable_path_sha256: authority.gh_executable_path_sha256,
    gh_version_output_sha256: authority.gh_version_output_sha256,
    verification_command_sha256: parsed.verification_command_sha256,
    verification_output_sha256: parsed.verification_output_sha256,
    verified_identity_sha256: parsed.verified_identity_sha256,
  });
}

export function assertProductionReleaseManifestSigstoreVerificationReceipt(
  value,
) {
  return normalizeReleaseManifestSigstoreVerificationReceipt(value);
}

export function canonicalReleaseManifestSigstoreVerificationReceiptText(
  value,
) {
  const normalized = normalizeReleaseManifestSigstoreVerificationReceipt(value);
  return `${JSON.stringify(normalized, null, 2)}\n`;
}

export function releaseManifestSigstoreVerificationReceiptSha256(value) {
  const canonicalText =
    canonicalReleaseManifestSigstoreVerificationReceiptText(value);
  return sha256(Buffer.concat([
    Buffer.from(
      RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_DOMAIN,
      "utf8",
    ),
    Buffer.from(canonicalText, "utf8"),
  ]));
}

function pathErrorCode(label) {
  return `${label}_path_invalid`;
}

function canonicalAbsolutePath(value, label) {
  if (
    typeof value !== "string"
    || value.length < 1
    || Buffer.byteLength(value, "utf8") > MAX_PATH_BYTES
    || value.includes("\0")
    || !path.isAbsolute(value)
    || path.normalize(value) !== value
    || path.resolve(value) !== value
  ) {
    reject(pathErrorCode(label));
  }
  return value;
}

function statIdentity(stats) {
  return Object.freeze({
    dev: stats.dev.toString(),
    ino: stats.ino.toString(),
    mode: stats.mode.toString(),
    nlink: stats.nlink.toString(),
    uid: stats.uid.toString(),
    gid: stats.gid.toString(),
    size: stats.size.toString(),
    mtime_ns: stats.mtimeNs.toString(),
    ctime_ns: stats.ctimeNs.toString(),
    birthtime_ns: stats.birthtimeNs.toString(),
  });
}

function sameIdentity(left, right) {
  const keys = Object.keys(left);
  return keys.length === Object.keys(right).length
    && keys.every((key) => left[key] === right[key]);
}

async function readExactHandleBytes(handle, expectedSize, label) {
  const size = Number(expectedSize);
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const result = await handle.read(bytes, offset, size - offset, offset);
    if (result.bytesRead < 1) reject(`${label}_changed_during_read`);
    offset += result.bytesRead;
  }
  const probe = Buffer.alloc(1);
  const trailing = await handle.read(probe, 0, 1, size);
  if (trailing.bytesRead !== 0) reject(`${label}_changed_during_read`);
  return bytes;
}

async function readStableBoundedFile(
  inputPath,
  {
    label,
    maxBytes,
    executable = false,
    exactBasename = "",
  },
) {
  const resolved = canonicalAbsolutePath(inputPath, label);
  if (exactBasename && path.basename(resolved) !== exactBasename) {
    reject(pathErrorCode(label));
  }

  let beforePath;
  let canonicalPath;
  try {
    [beforePath, canonicalPath] = await Promise.all([
      lstat(resolved, { bigint: true }),
      realpath(resolved),
    ]);
  } catch {
    reject(`${label}_read_failed`);
  }
  if (
    canonicalPath !== resolved
    || !beforePath.isFile()
    || beforePath.isSymbolicLink()
    || beforePath.nlink !== 1n
    || beforePath.size < 1n
    || beforePath.size > BigInt(maxBytes)
    || (executable && (beforePath.mode & 0o111n) === 0n)
  ) {
    reject(pathErrorCode(label));
  }

  let handle;
  try {
    const noFollow = typeof fsConstants.O_NOFOLLOW === "number"
      ? fsConstants.O_NOFOLLOW
      : 0;
    handle = await open(resolved, fsConstants.O_RDONLY | noFollow);
  } catch {
    reject(`${label}_read_failed`);
  }

  try {
    const beforeHandle = await handle.stat({ bigint: true });
    if (
      !beforeHandle.isFile()
      || !sameIdentity(statIdentity(beforePath), statIdentity(beforeHandle))
    ) {
      reject(`${label}_changed_during_read`);
    }
    const bytes = await readExactHandleBytes(handle, beforeHandle.size, label);
    const [afterHandle, afterPath, afterCanonicalPath] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(resolved, { bigint: true }),
      realpath(resolved),
    ]);
    const identity = statIdentity(beforeHandle);
    if (
      afterCanonicalPath !== resolved
      || !sameIdentity(identity, statIdentity(afterHandle))
      || !sameIdentity(identity, statIdentity(afterPath))
    ) {
      reject(`${label}_changed_during_read`);
    }
    return Object.freeze({
      path: resolved,
      bytes,
      sha256: sha256(bytes),
      identity,
    });
  } catch (error) {
    if (error instanceof ReleaseManifestSigstoreVerificationError) throw error;
    reject(`${label}_read_failed`);
  } finally {
    await handle.close();
  }
}

function decodeExactUtf8(bytes, label) {
  const text = bytes.toString("utf8");
  if (
    !Buffer.from(text, "utf8").equals(bytes)
    || text.includes("\0")
    || text.startsWith("\ufeff")
  ) {
    reject(`${label}_utf8_invalid`);
  }
  return text;
}

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch {
    reject(`${label}_json_invalid`);
  }
}

function validateManifestImage(rawImage, index, manifest) {
  const image = exactKeys(rawImage, IMAGE_KEYS, "release_manifest_image_invalid");
  const expectedName = IMAGE_NAMES[index];
  const expectedRepository =
    `ghcr.io/${RELEASE_MANIFEST_SIGSTORE_AUTHORITY.repository}/${expectedName}`;
  if (
    image.name !== expectedName
    || image.repository !== expectedRepository
    || typeof image.digest !== "string"
    || !SHA256.test(image.digest)
    || image.image !== `${expectedRepository}@${image.digest}`
    || image.platform !== RELEASE_PLATFORM
  ) {
    reject("release_manifest_image_invalid");
  }
  const subject = image.provenance_subject;
  if (
    !isRecord(subject)
    || subject.name !== expectedRepository
    || subject.digest !== image.digest
  ) {
    reject("release_manifest_image_invalid");
  }
  const verification = image.verification;
  if (
    !isRecord(verification)
    || verification.repo !== manifest.source_repository
    || verification.signer_workflow !== manifest.signer_workflow
    || verification.source_digest !== manifest.release_sha
    || verification.source_ref !== manifest.source_ref
    || verification.provenance_attestation !== "verified"
    || verification.sbom_attestation !== "verified"
  ) {
    reject("release_manifest_image_verification_invalid");
  }
  return image.digest;
}

function normalizeCanonicalReleaseManifest(file, expectedReleaseSha) {
  const text = decodeExactUtf8(file.bytes, "release_manifest");
  const value = exactKeys(
    parseJson(text, "release_manifest"),
    TOP_LEVEL_MANIFEST_KEYS,
    "release_manifest_fields_invalid",
  );
  if (`${JSON.stringify(value, null, 2)}\n` !== text) {
    reject("release_manifest_not_canonical");
  }
  if (
    value.schema !== RELEASE_SCHEMA
    || value.release_sha !== expectedReleaseSha
    || !RELEASE_SHA.test(value.release_sha)
    || value.source_ref !== RELEASE_MANIFEST_SIGSTORE_AUTHORITY.source_ref
    || value.source_repository
      !== RELEASE_MANIFEST_SIGSTORE_AUTHORITY.repository
    || value.signer_workflow
      !== RELEASE_MANIFEST_SIGSTORE_AUTHORITY.signer_workflow
    || value.platform !== RELEASE_PLATFORM
    || !/^[1-9][0-9]*$/.test(value.workflow_run_id)
    || value.workflow_run_url
      !== `https://github.com/${value.source_repository}/actions/runs/${value.workflow_run_id}`
  ) {
    reject("release_manifest_authority_invalid");
  }
  const generatedAt = new Date(value.generated_at);
  if (
    Number.isNaN(generatedAt.getTime())
    || generatedAt.toISOString() !== value.generated_at
  ) {
    reject("release_manifest_authority_invalid");
  }
  if (!Array.isArray(value.images) || value.images.length !== IMAGE_NAMES.length) {
    reject("release_manifest_images_invalid");
  }
  const imageDigests = value.images.map((image, index) => (
    validateManifestImage(image, index, value)
  ));
  if (new Set(imageDigests).size !== imageDigests.length) {
    reject("release_manifest_images_invalid");
  }
  return Object.freeze({
    releaseSha: value.release_sha,
    sourceRef: value.source_ref,
    repository: value.source_repository,
    signerWorkflow: value.signer_workflow,
    manifestSha256: file.sha256,
    manifestBareSha256: file.sha256.slice("sha256:".length),
  });
}

function normalizeBundle(file) {
  const text = decodeExactUtf8(file.bytes, "release_bundle");
  const value = parseJson(text, "release_bundle");
  if (
    !isRecord(value)
    || typeof value.mediaType !== "string"
    || !SIGSTORE_BUNDLE_MEDIA_TYPE.test(value.mediaType)
    || !isRecord(value.verificationMaterial)
    || !isRecord(value.dsseEnvelope)
    || value.dsseEnvelope.payloadType !== "application/vnd.in-toto+json"
    || typeof value.dsseEnvelope.payload !== "string"
    || value.dsseEnvelope.payload.length < 1
    || !Array.isArray(value.dsseEnvelope.signatures)
    || value.dsseEnvelope.signatures.length < 1
    || value.dsseEnvelope.signatures.some((signature) => (
      !isRecord(signature)
      || typeof signature.sig !== "string"
      || signature.sig.length < 1
    ))
  ) {
    reject("release_bundle_shape_invalid");
  }
  return Object.freeze({
    mediaType: value.mediaType,
    payload: value.dsseEnvelope.payload,
    payloadType: value.dsseEnvelope.payloadType,
    signatures: Object.freeze(
      value.dsseEnvelope.signatures.map((signature) => signature.sig),
    ),
    bundleSha256: file.sha256,
  });
}

function normalizeReleaseSha(value) {
  if (typeof value !== "string" || !RELEASE_SHA.test(value)) {
    reject("expected_release_sha_invalid");
  }
  return value;
}

function normalizeToolAuthority(value) {
  const authority = exactKeys(
    value,
    ["path", "version", "sha256"],
    "gh_tool_authority_invalid",
  );
  const toolPath = canonicalAbsolutePath(authority.path, "gh_tool");
  if (
    path.basename(toolPath) !== "gh"
    || typeof authority.version !== "string"
    || !/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(
      authority.version,
    )
    || typeof authority.sha256 !== "string"
    || !SHA256.test(authority.sha256)
  ) {
    reject("gh_tool_authority_invalid");
  }
  return Object.freeze({
    path: toolPath,
    version: authority.version,
    sha256: authority.sha256,
  });
}

export function releaseManifestSigstoreVerificationArgs({
  manifestPath,
  bundlePath,
  releaseSha,
}) {
  canonicalAbsolutePath(manifestPath, "release_manifest");
  canonicalAbsolutePath(bundlePath, "release_bundle");
  normalizeReleaseSha(releaseSha);
  return Object.freeze([
    "attestation",
    "verify",
    manifestPath,
    "--bundle",
    bundlePath,
    "--repo",
    RELEASE_MANIFEST_SIGSTORE_AUTHORITY.repository,
    "--signer-workflow",
    RELEASE_MANIFEST_SIGSTORE_AUTHORITY.signer_workflow,
    "--source-digest",
    releaseSha,
    "--source-ref",
    RELEASE_MANIFEST_SIGSTORE_AUTHORITY.source_ref,
    "--deny-self-hosted-runners",
    "--format",
    "json",
  ]);
}

function runnerOptions(cwd, timeout, maxBuffer) {
  return Object.freeze({
    cwd,
    env: MINIMAL_GH_ENVIRONMENT,
    encoding: "utf8",
    stdio: Object.freeze(["ignore", "pipe", "pipe"]),
    timeout,
    maxBuffer,
    shell: false,
    windowsHide: true,
  });
}

function productionRunner(command, args, options) {
  return spawnSync(command, args, options);
}

async function invokeRunner(runner, command, args, options, label) {
  let result;
  try {
    result = await runner(command, args, options);
  } catch {
    reject(`${label}_runner_failed`);
  }
  if (!isRecord(result)) reject(`${label}_runner_result_invalid`);
  const stdout = result.stdout;
  const stderr = result.stderr;
  if (typeof stdout !== "string" || typeof stderr !== "string") {
    reject(`${label}_runner_result_invalid`);
  }
  const maxBytes = options.maxBuffer;
  if (
    Buffer.byteLength(stdout, "utf8") > maxBytes
    || Buffer.byteLength(stderr, "utf8") > maxBytes
  ) {
    reject(`${label}_output_oversize`);
  }
  if (result.error?.code === "ETIMEDOUT") reject(`${label}_timeout`);
  if (
    result.error
    || result.signal !== null && result.signal !== undefined
    || result.status !== 0
  ) {
    reject(`${label}_failed`);
  }
  return stdout;
}

function validateGhVersionOutput(stdout, expectedVersion) {
  const lines = stdout.replace(/\n$/, "").split("\n");
  if (
    lines.length !== 2
    || !new RegExp(
      `^gh version ${expectedVersion.replaceAll(".", "\\.")} \\([0-9]{4}-[0-9]{2}-[0-9]{2}\\)$`,
    ).test(lines[0])
    || lines[1]
      !== `https://github.com/cli/cli/releases/tag/v${expectedVersion}`
  ) {
    reject("gh_version_output_invalid");
  }
}

function exactWorkflowIdentity(manifest) {
  return `https://github.com/${manifest.signerWorkflow}@${manifest.sourceRef}`;
}

function validateOutputBundleBinding(attestation, bundle) {
  if (!isRecord(attestation) || !isRecord(attestation.bundle)) {
    reject("gh_attestation_output_bundle_invalid");
  }
  const outputBundle = attestation.bundle;
  const envelope = outputBundle.dsseEnvelope;
  if (
    outputBundle.mediaType !== bundle.mediaType
    || !isRecord(envelope)
    || envelope.payload !== bundle.payload
    || envelope.payloadType !== bundle.payloadType
    || !Array.isArray(envelope.signatures)
    || envelope.signatures.length !== bundle.signatures.length
    || envelope.signatures.some((signature, index) => (
      !isRecord(signature) || signature.sig !== bundle.signatures[index]
    ))
  ) {
    reject("gh_attestation_output_bundle_invalid");
  }
}

function validateStatement(statement, manifest) {
  if (
    !isRecord(statement)
    || statement._type !== SLSA_STATEMENT_TYPE
    || statement.predicateType
      !== RELEASE_MANIFEST_SIGSTORE_AUTHORITY.predicate_type
    || !Array.isArray(statement.subject)
    || statement.subject.length !== 1
  ) {
    reject("gh_attestation_statement_invalid");
  }
  const subject = statement.subject[0];
  if (
    !isRecord(subject)
    || subject.name !== RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename
    || !isRecord(subject.digest)
    || subject.digest.sha256 !== manifest.manifestBareSha256
    || !BARE_SHA256.test(subject.digest.sha256)
  ) {
    reject("gh_attestation_subject_invalid");
  }

  const buildDefinition = statement.predicate?.buildDefinition;
  const workflow = buildDefinition?.externalParameters?.workflow;
  const dependencies = buildDefinition?.resolvedDependencies;
  const sourceRepositoryUri = `https://github.com/${manifest.repository}`;
  const expectedDependency = `git+${sourceRepositoryUri}@${manifest.sourceRef}`;
  if (
    !isRecord(buildDefinition)
    || !isRecord(workflow)
    || workflow.repository !== sourceRepositoryUri
    || workflow.path !== ".github/workflows/build-tee-images.yml"
    || workflow.ref !== manifest.sourceRef
    || !Array.isArray(dependencies)
    || !dependencies.some((dependency) => (
      isRecord(dependency)
      && dependency.uri === expectedDependency
      && dependency.digest?.gitCommit === manifest.releaseSha
    ))
    || statement.predicate?.runDetails?.builder?.id
      !== exactWorkflowIdentity(manifest)
  ) {
    reject("gh_attestation_statement_source_invalid");
  }
}

function validateCertificate(certificate, manifest) {
  const sourceRepositoryUri = `https://github.com/${manifest.repository}`;
  const workflowIdentity = exactWorkflowIdentity(manifest);
  if (
    !isRecord(certificate)
    || certificate.issuer !== GITHUB_OIDC_ISSUER
    || certificate.runnerEnvironment !== GITHUB_HOSTED_RUNNER
    || certificate.sourceRepositoryURI !== sourceRepositoryUri
    || certificate.sourceRepositoryDigest !== manifest.releaseSha
    || certificate.sourceRepositoryRef !== manifest.sourceRef
    || certificate.subjectAlternativeName !== workflowIdentity
    || certificate.buildSignerURI !== workflowIdentity
    || certificate.buildConfigURI !== workflowIdentity
    || certificate.githubWorkflowRepository !== manifest.repository
    || certificate.githubWorkflowSHA !== manifest.releaseSha
    || certificate.githubWorkflowRef !== manifest.sourceRef
  ) {
    reject("gh_attestation_certificate_identity_invalid");
  }
}

function validateGhAttestationOutput(stdout, manifest, bundle) {
  if (Buffer.byteLength(stdout, "utf8") < 2) {
    reject("gh_attestation_output_invalid");
  }
  const parsed = parseJson(stdout, "gh_attestation_output");
  if (!Array.isArray(parsed) || parsed.length !== 1) {
    reject("gh_attestation_output_count_invalid");
  }
  const entry = exactKeys(
    parsed[0],
    ["attestation", "verificationResult"],
    "gh_attestation_output_fields_invalid",
  );
  validateOutputBundleBinding(entry.attestation, bundle);
  const result = entry.verificationResult;
  if (
    !isRecord(result)
    || !Array.isArray(result.verifiedTimestamps)
    || result.verifiedTimestamps.length < 1
  ) {
    reject("gh_attestation_verification_result_invalid");
  }
  validateStatement(result.statement, manifest);
  validateCertificate(result.signature?.certificate, manifest);
}

async function assertSnapshotsUnchanged(initial, label, options) {
  let current;
  try {
    current = await readStableBoundedFile(initial.path, options);
  } catch {
    reject(`${label}_changed_after_verification`);
  }
  if (
    current.sha256 !== initial.sha256
    || !sameIdentity(current.identity, initial.identity)
  ) {
    reject(`${label}_changed_after_verification`);
  }
}

function receipt({
  production,
  manifest,
  bundle,
  tool,
  versionOutput,
  args,
  verificationOutput,
}) {
  const commandCommitment = domainSha256(
    "dnai.tee-image-release-manifest-sigstore-command.v1",
    canonicalCompactJson([tool.path, ...args]),
  );
  const identityCommitment = expectedVerifiedIdentitySha256(
    manifest.releaseSha,
    manifest.manifestSha256,
  );
  return Object.freeze({
    schema: RELEASE_MANIFEST_SIGSTORE_VERIFICATION_SCHEMA,
    status: production
      ? "verified_by_pinned_gh_sigstore"
      : "test_adapter_verified_not_release_authority",
    blocker_code: RELEASE_MANIFEST_SIGSTORE_BLOCKER,
    blocker_status: production
      ? "cleared_by_this_receipt"
      : "not_cleared_by_test_adapter",
    release_sha: manifest.releaseSha,
    release_manifest_sha256: manifest.manifestSha256,
    release_manifest_sigstore_bundle_sha256: bundle.bundleSha256,
    gh_executable_sha256: tool.sha256,
    gh_executable_path_sha256: domainSha256(
      "dnai.pinned-gh-executable-path.v1",
      tool.path,
    ),
    gh_version_output_sha256: sha256(Buffer.from(versionOutput, "utf8")),
    verification_command_sha256: commandCommitment,
    verification_output_sha256: sha256(
      Buffer.from(verificationOutput, "utf8"),
    ),
    verified_identity_sha256: identityCommitment,
  });
}

async function verifyInternal(input, { runner, toolAuthority, production }) {
  const normalizedInput = exactKeys(
    input,
    ["manifestPath", "bundlePath", "expectedReleaseSha"],
    "verification_input_fields_invalid",
  );
  const releaseSha = normalizeReleaseSha(normalizedInput.expectedReleaseSha);
  const manifestPath = canonicalAbsolutePath(
    normalizedInput.manifestPath,
    "release_manifest",
  );
  const bundlePath = canonicalAbsolutePath(
    normalizedInput.bundlePath,
    "release_bundle",
  );
  if (path.dirname(manifestPath) !== path.dirname(bundlePath)) {
    reject("release_inputs_directory_mismatch");
  }
  const tool = normalizeToolAuthority(toolAuthority);
  const [manifestFile, bundleFile, toolFile] = await Promise.all([
    readStableBoundedFile(manifestPath, {
      label: "release_manifest",
      maxBytes: MAX_RELEASE_MANIFEST_BYTES,
      exactBasename: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
    }),
    readStableBoundedFile(bundlePath, {
      label: "release_bundle",
      maxBytes: MAX_RELEASE_BUNDLE_BYTES,
      exactBasename: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.bundle_filename,
    }),
    readStableBoundedFile(tool.path, {
      label: "gh_tool",
      maxBytes: MAX_GH_EXECUTABLE_BYTES,
      executable: true,
      exactBasename: "gh",
    }),
  ]);
  if (toolFile.sha256 !== tool.sha256) reject("gh_tool_digest_mismatch");

  const manifest = normalizeCanonicalReleaseManifest(manifestFile, releaseSha);
  const bundle = normalizeBundle(bundleFile);
  const cwd = path.dirname(manifestPath);
  const versionArgs = Object.freeze(["--version"]);
  const versionOutput = await invokeRunner(
    runner,
    tool.path,
    versionArgs,
    runnerOptions(
      cwd,
      GH_VERSION_TIMEOUT_MS,
      MAX_GH_VERSION_OUTPUT_BYTES,
    ),
    "gh_version",
  );
  validateGhVersionOutput(versionOutput, tool.version);

  const args = releaseManifestSigstoreVerificationArgs({
    manifestPath,
    bundlePath,
    releaseSha,
  });
  const verificationOutput = await invokeRunner(
    runner,
    tool.path,
    args,
    runnerOptions(
      cwd,
      GH_ATTESTATION_TIMEOUT_MS,
      MAX_GH_ATTESTATION_OUTPUT_BYTES,
    ),
    "gh_attestation_verification",
  );
  validateGhAttestationOutput(verificationOutput, manifest, bundle);

  await Promise.all([
    assertSnapshotsUnchanged(manifestFile, "release_manifest", {
      label: "release_manifest",
      maxBytes: MAX_RELEASE_MANIFEST_BYTES,
      exactBasename: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
    }),
    assertSnapshotsUnchanged(bundleFile, "release_bundle", {
      label: "release_bundle",
      maxBytes: MAX_RELEASE_BUNDLE_BYTES,
      exactBasename: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.bundle_filename,
    }),
    assertSnapshotsUnchanged(toolFile, "gh_tool", {
      label: "gh_tool",
      maxBytes: MAX_GH_EXECUTABLE_BYTES,
      executable: true,
      exactBasename: "gh",
    }),
  ]);

  const result = receipt({
    production,
    manifest,
    bundle,
    tool,
    versionOutput,
    args,
    verificationOutput,
  });
  return production
    ? normalizeReleaseManifestSigstoreVerificationReceipt(result)
    : result;
}

export async function verifyReleaseManifestSigstoreAttestation(
  input,
  ...forbiddenAdapters
) {
  if (forbiddenAdapters.length !== 0) {
    reject("production_adapter_injection_forbidden");
  }
  return verifyInternal(input, {
    runner: productionRunner,
    toolAuthority: PINNED_GH_TOOL,
    production: true,
  });
}

export async function verifyReleaseManifestSigstoreAttestationWithTestAdapter(
  input,
  adapter,
) {
  const normalizedAdapter = exactKeys(
    adapter,
    ["runner", "toolAuthority"],
    "test_adapter_fields_invalid",
  );
  if (typeof normalizedAdapter.runner !== "function") {
    reject("test_adapter_runner_invalid");
  }
  return verifyInternal(input, {
    runner: normalizedAdapter.runner,
    toolAuthority: normalizedAdapter.toolAuthority,
    production: false,
  });
}
