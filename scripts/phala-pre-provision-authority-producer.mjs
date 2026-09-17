#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { normalizePhalaKmsContract } from "./phala-contract-kms-core.mjs";
import { assertCanonicalPlainDataGraph } from "./canonical-authority-graph.mjs";

import {
  canonicalCvmLaunchIntentCoreArtifactText,
  canonicalFreshContractDeploymentReceiptText,
  cvmLaunchIntentCoreDigest,
  freshContractDeploymentReceiptDigest,
  normalizeFreshContractDeploymentReceipt,
  parseCvmLaunchIntentCoreText,
} from "./cvm-launch-intent-core.mjs";
import {
  createFreshCvmDescriptorRuntimeAuthority,
  readFreshCvmDescriptorRuntimeMaterials,
} from "./cvm-descriptor-runtime-authority-v3.mjs";
import {
  validateCanonicalGeneratedCvmDescriptorSet,
} from "./cvm-release-descriptor-set-v3.mjs";
import {
  assertPinnedPhalaPrivateDirectoryPathIdentity,
  closePhalaPinnedPrivateDirectory,
  pinPhalaPrivateDirectory,
  publishPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";
import {
  assertSafePhalaSdkProcessEnvironment,
  createPinnedPhalaPreProvisionStagingSession,
  observePinnedPhalaCompatibility,
  publishPinnedPhalaPreProvisionStagingReceipt,
} from "./phala-production-sdk-adapter.mjs";
import {
  canonicalPhalaCompatibilityReceiptText,
  canonicalPhalaProductionTargetAuthorityText,
  canonicalPhalaSdkWireTransformStagingReceiptText,
  assertSecretFreePhalaAuthorityArtifact,
  normalizePhalaCompatibilityReceipt,
  normalizePhalaProductionTargetAuthority,
  normalizePhalaSdkWireTransformStagingReceipt,
} from "./phala-production-target-authority.mjs";
import {
  canonicalBootstrapPublicEnvironmentAuthorityText,
} from "./phala-bootstrap-public-environment-authority-core.mjs";
import {
  AUTHORITY_REVIEW_RECEIPT_SCHEMA,
  CVM_LAUNCH_INTENT_ACTION_SCOPE,
  REVIEW_SUBJECT_POLICY,
  canonicalArtifactText,
  describeAuthorityReviewSubjectText,
  parseAuthorityReviewEnvelopeText,
  parseDeploymentIntentCoreText,
  parseFreshContractDeploymentReceiptText,
} from "./operator-policy-packet-core.mjs";
import {
  canonicalPhalaQvlMeasurementPolicySetText,
  normalizePhalaQvlMeasurementPolicySet,
  phalaQvlMeasurementPolicySetSha256,
} from "./phala-seven-cvm-measurement-policy.mjs";
import {
  canonicalReleaseManifestSigstoreVerificationReceiptText,
  normalizeReleaseManifestSigstoreVerificationReceipt,
  releaseManifestSigstoreVerificationReceiptSha256,
} from "./release-manifest-sigstore-verifier.mjs";
import {
  normalizeTinkerAccountBindingCeremonyReceipt,
  tinkerAccountBindingCeremonyReceiptSha256,
} from "./tinker-account-binding-ceremony.mjs";
import {
  canonicalPhalaProducerJsonText,
  capturePhalaSdkWireTransformStagingReceipt,
  createBootstrapPublicEnvironmentReviewInput,
  createPhalaProductionTargetReviewInput,
  finalizeBootstrapPublicEnvironmentAuthority,
  finalizePhalaProductionTargetAuthority,
  normalizePhalaProductionTargetReviewInput,
  phalaProductionTargetReviewInputDigest,
} from "./phala-pre-provision-authority-producer-core.mjs";

const MAX_INPUT_BYTES = 4 * 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const SYSTEM_PYTHON = "/usr/bin/python3";
const PINNED_PARENT_READ_HELPER = String.raw`
import os, re, stat, sys

def die(message):
    sys.stderr.write(message + "\n")
    raise SystemExit(1)

name = sys.argv[1]
maximum = int(sys.argv[2])
expected_parent = tuple(int(value) for value in sys.argv[3:8])
if re.fullmatch(r"[^/\x00-\x1f\x7f]{1,255}", name) is None or name in (".", ".."):
    die("invalid descriptor-relative input basename")
parent = os.fstat(3)
observed_parent = (parent.st_dev, parent.st_ino, parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode))
if not stat.S_ISDIR(parent.st_mode) or observed_parent != expected_parent:
    die("pinned input parent descriptor identity changed")
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
if getattr(os, "O_NOFOLLOW", None) is None:
    die("descriptor-relative no-follow input reads are unavailable")
fd = os.open(name, flags, dir_fd=3)
try:
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size < 2 or before.st_size > maximum):
        die("descriptor-relative input is not an owned bounded single-link non-writable regular file")
    chunks = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(fd, min(remaining, 65536))
        if not chunk:
            die("descriptor-relative input ended during its bounded read")
        chunks.append(chunk)
        remaining -= len(chunk)
    after = os.fstat(fd)
    current = os.stat(name, dir_fd=3, follow_symlinks=False)
    fields_before = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                     before.st_gid, before.st_nlink, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns)
    fields_after = (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                    after.st_gid, after.st_nlink, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)
    fields_current = (current.st_dev, current.st_ino, current.st_mode, current.st_uid,
                      current.st_gid, current.st_nlink, current.st_size,
                      current.st_mtime_ns, current.st_ctime_ns)
    data = b"".join(chunks)
    if fields_before != fields_after or fields_after != fields_current or len(data) != before.st_size:
        die("descriptor-relative input changed during its bounded read")
    sys.stdout.buffer.write(data)
finally:
    os.close(fd)
`;

export const PHALA_PRE_PROVISION_AUTHORITY_PRODUCER_USAGE = `Usage:
  node scripts/phala-pre-provision-authority-producer.mjs observe-compatibility \\
    --out /absolute/private/phala-compatibility-receipt.json

  node scripts/phala-pre-provision-authority-producer.mjs init-kms-signer-provenance \\
    --kms-contract-id kc_REVIEWED --ca-pubkey DER_SPKI_HEX \\
    --env-encrypt-signer-k256 0x02... \\
    --valid-from UTC_SECOND --valid-until UTC_SECOND \\
    --out /absolute/private/kms-signer-provenance.json

  node scripts/phala-pre-provision-authority-producer.mjs init-target-input \\
    --compatibility /absolute/private/phala-compatibility-receipt.json \\
    --cvm-launch-intent /absolute/private/cvm-launch-intent-core.json \\
    --deployment-intent /absolute/private/deployment-intent-core.json \\
    --fresh-contract-deployment-receipt /absolute/private/fresh-contract-deployment-receipt.json \\
    --tinker-account-binding-ceremony-receipt /absolute/private/tinker-account-binding-ceremony.receipt.json \\
    --cvm-launch-review-envelope /absolute/private/cvm-launch-review-envelope.json \\
    --cvm-launch-review-evidence /absolute/private/cvm-launch-review-evidence.json \\
    --kms-signer-provenance /absolute/private/kms-signer-provenance.json \\
    --out /absolute/private/phala-production-target.review-input.json

  node scripts/phala-pre-provision-authority-producer.mjs observe-staging \\
    --compatibility /absolute/private/phala-compatibility-receipt.json \\
    --target-input /absolute/private/phala-production-target.review-input.json \\
    --cvm-launch-intent /absolute/private/cvm-launch-intent-core.json \\
    --deployment-intent /absolute/private/deployment-intent-core.json \\
    --fresh-contract-deployment-receipt /absolute/private/fresh-contract-deployment-receipt.json \\
    --tinker-account-binding-ceremony-receipt /absolute/private/tinker-account-binding-ceremony.receipt.json \\
    --cvm-launch-review-envelope /absolute/private/cvm-launch-review-envelope.json \\
    --cvm-launch-review-evidence /absolute/private/cvm-launch-review-evidence.json \\
    --kms-signer-provenance /absolute/private/kms-signer-provenance.json \\
    --release-directory /absolute/repository/.release \\
    --confirm-dedicated-staging-workspace true \\
    --out /absolute/private/empty-staging-attempt/phala-sdk-wire-transform-staging-receipt.json

  node scripts/phala-pre-provision-authority-producer.mjs finalize-target \\
    --compatibility /absolute/private/phala-compatibility-receipt.json \\
    --staging /absolute/private/phala-sdk-wire-transform-staging-receipt.json \\
    --target-input /absolute/private/phala-production-target.review-input.json \\
    --cvm-launch-intent /absolute/private/cvm-launch-intent-core.json \\
    --deployment-intent /absolute/private/deployment-intent-core.json \\
    --fresh-contract-deployment-receipt /absolute/private/fresh-contract-deployment-receipt.json \\
    --tinker-account-binding-ceremony-receipt /absolute/private/tinker-account-binding-ceremony.receipt.json \\
    --cvm-launch-review-envelope /absolute/private/cvm-launch-review-envelope.json \\
    --cvm-launch-review-evidence /absolute/private/cvm-launch-review-evidence.json \\
    --kms-signer-provenance /absolute/private/kms-signer-provenance.json \\
    --out /absolute/private/phala-production-target-authority.json

  node scripts/phala-pre-provision-authority-producer.mjs init-bootstrap-input \\
    --compatibility /absolute/private/phala-compatibility-receipt.json \\
    --staging /absolute/private/phala-sdk-wire-transform-staging-receipt.json \\
    --target /absolute/private/phala-production-target-authority.json \\
    --release-directory /absolute/repository/.release \\
    --deployment-intent /absolute/private/deployment-intent-core.json \\
    --deployment-transaction-plan /absolute/private/deployment-transaction-plan.json \\
    --fresh-contract-deployment-receipt /absolute/private/fresh-contract-deployment-receipt.json \\
    --image-release-sigstore-verification-receipt /absolute/private/release-manifest-sigstore-verification-receipt.json \\
    --cvm-launch-intent /absolute/private/cvm-launch-intent-core.json \\
    --cvm-launch-review-receipt /absolute/private/cvm-launch-review.receipt.json \\
    --qvl-measurement-policy-set /absolute/private/qvl-measurement-policy-set.json \\
    --out /absolute/private/phala-bootstrap-public-environment.review-input.json

  node scripts/phala-pre-provision-authority-producer.mjs finalize-bootstrap \\
    --compatibility /absolute/private/phala-compatibility-receipt.json \\
    --staging /absolute/private/phala-sdk-wire-transform-staging-receipt.json \\
    --target /absolute/private/phala-production-target-authority.json \\
    --bootstrap-input /absolute/private/phala-bootstrap-public-environment.review-input.json \\
    --release-directory /absolute/repository/.release \\
    --deployment-intent /absolute/private/deployment-intent-core.json \\
    --deployment-transaction-plan /absolute/private/deployment-transaction-plan.json \\
    --fresh-contract-deployment-receipt /absolute/private/fresh-contract-deployment-receipt.json \\
    --image-release-sigstore-verification-receipt /absolute/private/release-manifest-sigstore-verification-receipt.json \\
    --cvm-launch-intent /absolute/private/cvm-launch-intent-core.json \\
    --cvm-launch-review-receipt /absolute/private/cvm-launch-review.receipt.json \\
    --qvl-measurement-policy-set /absolute/private/qvl-measurement-policy-set.json \\
    --lifetime-seconds 600 \\
    --out /absolute/private/phala-bootstrap-public-environment-authority.json

Every output is canonical, mode 0600, descriptor-relative, and no-clobber in an
existing operator-owned mode-0700 directory. observe-staging requires a dedicated
empty output directory, verifies zero authenticated committed CVMs, and durably
journals one app-id reservation plus exactly seven prepare-only provisionCvm
requests. It makes no exclusivity or server-cleanup claim; its session has no
commit method and automatic retry is forbidden. No command accepts a token,
secret, origin, API version,
generic request, replacement mode, or output-content override.`;

const TARGET_SOURCE_FLAGS = Object.freeze([
  "--cvm-launch-intent",
  "--deployment-intent",
  "--fresh-contract-deployment-receipt",
  "--tinker-account-binding-ceremony-receipt",
  "--cvm-launch-review-envelope",
  "--cvm-launch-review-evidence",
  "--kms-signer-provenance",
]);
const BOOTSTRAP_SOURCE_FLAGS = Object.freeze([
  "--release-directory",
  "--deployment-intent",
  "--deployment-transaction-plan",
  "--fresh-contract-deployment-receipt",
  "--image-release-sigstore-verification-receipt",
  "--cvm-launch-intent",
  "--cvm-launch-review-receipt",
  "--qvl-measurement-policy-set",
]);

const COMMAND_FLAGS = Object.freeze({
  "observe-compatibility": ["--out"],
  "init-kms-signer-provenance": [
    "--kms-contract-id", "--ca-pubkey", "--env-encrypt-signer-k256",
    "--valid-from", "--valid-until", "--out",
  ],
  "init-target-input": [
    "--compatibility", ...TARGET_SOURCE_FLAGS, "--out",
  ],
  "observe-staging": [
    "--compatibility", "--target-input", "--release-directory",
    ...TARGET_SOURCE_FLAGS,
    "--confirm-dedicated-staging-workspace", "--out",
  ],
  "finalize-target": [
    "--compatibility", "--staging", "--target-input", ...TARGET_SOURCE_FLAGS, "--out",
  ],
  "init-bootstrap-input": [
    "--compatibility", "--staging", "--target", ...BOOTSTRAP_SOURCE_FLAGS, "--out",
  ],
  "finalize-bootstrap": [
    "--compatibility", "--staging", "--target", "--bootstrap-input",
    ...BOOTSTRAP_SOURCE_FLAGS, "--lifetime-seconds", "--out",
  ],
});

function canonicalAbsolute(value, label, { existing = true } = {}) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value) {
    throw new Error(`${label} must be a canonical absolute path`);
  }
  if (existing && fs.realpathSync.native(value) !== value) {
    throw new Error(`${label} must not traverse a symlink or filesystem alias`);
  }
  return value;
}

export function parsePhalaPreProvisionAuthorityProducerArgs(argv) {
  if (!Array.isArray(argv) || argv.length === 0
    || argv[0] === "help" || argv[0] === "--help" || argv[0] === "-h") {
    return { command: "help" };
  }
  const command = argv[0];
  const required = COMMAND_FLAGS[command];
  if (!required) throw new Error("unknown Phala pre-provision producer command");
  if ((argv.length - 1) % 2 !== 0) {
    throw new Error("producer arguments must be unique --flag value pairs");
  }
  const values = {};
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!required.includes(flag) || Object.hasOwn(values, flag)) {
      throw new Error("producer argument is unknown or duplicated");
    }
    values[flag] = value;
  }
  if (required.some((flag) => !Object.hasOwn(values, flag))) {
    throw new Error("producer command is missing a required argument");
  }
  return { command, values };
}

export function readStableBytes(filePath, label) {
  canonicalAbsolute(filePath, label);
  const python = fs.lstatSync(SYSTEM_PYTHON, { bigint: true });
  if (!python.isFile() || python.isSymbolicLink()
    || python.uid !== 0n || (python.mode & 0o022n) !== 0n
    || (python.mode & 0o111n) === 0n) {
    throw new Error("root-owned isolated system Python is unavailable for stable input reads");
  }
  const parentPath = path.dirname(filePath);
  const parentBefore = fs.lstatSync(parentPath, { bigint: true });
  if (!parentBefore.isDirectory() || parentBefore.isSymbolicLink()
    || parentBefore.uid !== BigInt(process.getuid())
    || (parentBefore.mode & 0o022n) !== 0n
    || fs.realpathSync.native(parentPath) !== parentPath) {
    throw new Error(`${label} parent must be owned, non-writable, and canonical`);
  }
  const parentFd = fs.openSync(
    parentPath,
    fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW,
  );
  try {
    const parentOpened = fs.fstatSync(parentFd, { bigint: true });
    const parentFields = ["dev", "ino", "mode", "uid", "gid"];
    if (parentFields.some((field) => parentBefore[field] !== parentOpened[field])) {
      throw new Error(`${label} parent changed while pinned`);
    }
    const result = spawnSync(SYSTEM_PYTHON, [
      "-I", "-S", "-B", "-c", PINNED_PARENT_READ_HELPER,
      path.basename(filePath),
      String(MAX_INPUT_BYTES),
      String(parentOpened.dev),
      String(parentOpened.ino),
      String(parentOpened.uid),
      String(parentOpened.gid),
      String(parentOpened.mode & 0o777n),
    ], {
      cwd: "/",
      env: {},
      maxBuffer: MAX_INPUT_BYTES + 64 * 1024,
      stdio: ["ignore", "pipe", "pipe", parentFd],
    });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(result.stderr?.toString("utf8").trim()
        || `${label} descriptor-relative read failed closed`);
    }
    const parentAfter = fs.lstatSync(parentPath, { bigint: true });
    if (parentFields.some((field) => parentOpened[field] !== parentAfter[field])
      || fs.realpathSync.native(parentPath) !== parentPath) {
      throw new Error(`${label} parent changed during its pinned read`);
    }
    return result.stdout;
  } finally {
    fs.closeSync(parentFd);
  }
}

function readCanonicalJson(filePath, label) {
  const { value, bytes } = readStableJson(filePath, label);
  if (canonicalPhalaProducerJsonText(value) !== bytes.toString("utf8")) {
    throw new Error(`${label} is not canonical recursively sorted JSON`);
  }
  return { value, bytes };
}

function readStableJson(filePath, label) {
  const bytes = readStableBytes(filePath, label);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(`${label} is not JSON`);
  }
  canonicalPhalaProducerJsonText(value);
  return { value, bytes };
}

function rawSha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function requireValid(result, label) {
  if (!result?.ok) throw new Error(`${label} failed its authoritative validator`);
  return result;
}

export function readValidatedTargetReviewDependencies(values) {
  const launchBytes = readStableBytes(values["--cvm-launch-intent"], "CVM launch intent");
  const launch = parseCvmLaunchIntentCoreText(launchBytes.toString("utf8"));
  if (canonicalCvmLaunchIntentCoreArtifactText(launch) !== launchBytes.toString("utf8")) {
    throw new Error("CVM launch intent is noncanonical");
  }
  const subjectDescriptor = requireValid(
    describeAuthorityReviewSubjectText(launchBytes.toString("utf8")),
    "CVM launch review subject",
  );
  const deploymentFile = readStableBytes(
    values["--deployment-intent"],
    "deployment intent",
  );
  const deployment = requireValid(
    parseDeploymentIntentCoreText(deploymentFile.toString("utf8")),
    "deployment intent",
  );
  const tinkerFile = readStableJson(
    values["--tinker-account-binding-ceremony-receipt"],
    "Tinker account-binding ceremony receipt",
  );
  const tinkerReceipt = normalizeTinkerAccountBindingCeremonyReceipt(tinkerFile.value);
  if (canonicalArtifactText(tinkerReceipt) !== tinkerFile.bytes.toString("utf8")) {
    throw new Error("Tinker account-binding ceremony receipt is noncanonical");
  }
  const tinkerReceiptSha256 = tinkerAccountBindingCeremonyReceiptSha256(tinkerReceipt);
  const freshFile = readStableBytes(
    values["--fresh-contract-deployment-receipt"],
    "fresh-contract deployment receipt",
  );
  const freshReceipt = requireValid(parseFreshContractDeploymentReceiptText(
    freshFile.toString("utf8"),
    {
      expectedDeploymentIntentSha256:
        deployment.receipt.deploymentIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        deployment.intent.release.reviewerAuthorityGenesisAcceptanceSha256,
      expectedTinkerAccountBindingCeremonyReceiptSha256: tinkerReceiptSha256,
    },
  ), "fresh-contract deployment receipt");
  const reviewEnvelopeFile = readStableBytes(
    values["--cvm-launch-review-envelope"],
    "CVM launch review envelope",
  );
  const review = requireValid(parseAuthorityReviewEnvelopeText(
    reviewEnvelopeFile.toString("utf8"),
    {
      checkedAtMs: Date.now(),
      subjectDescriptor,
      authorityDependencies: {
        deploymentIntent: deployment.intent,
        freshContractDeploymentReceipt: freshReceipt.receipt,
        tinkerAccountBindingCeremonyReceipt: tinkerReceipt,
      },
    },
  ), "CVM launch review envelope");
  const reviewEvidenceFile = readCanonicalJson(
    values["--cvm-launch-review-evidence"],
    "CVM launch review evidence",
  );
  assertSecretFreePhalaAuthorityArtifact(
    reviewEvidenceFile.value,
    "CVM launch review evidence",
  );
  if (rawSha256(reviewEvidenceFile.bytes) !== review.envelope.review_evidence_sha256) {
    throw new Error("CVM launch review evidence bytes do not match the review envelope");
  }
  return {
    launch,
    launch_sha256: subjectDescriptor.subjectSha256,
    review_envelope_sha256: review.receipt.reviewEnvelopeSha256,
    review_evidence_sha256: review.receipt.reviewEvidenceSha256,
    source_sha256: {
      cvm_launch_intent: rawSha256(launchBytes),
      deployment_intent: rawSha256(deploymentFile),
      fresh_contract_deployment_receipt: rawSha256(freshFile),
      tinker_account_binding_ceremony_receipt: rawSha256(tinkerFile.bytes),
      cvm_launch_review_envelope: rawSha256(reviewEnvelopeFile),
      cvm_launch_review_evidence: rawSha256(reviewEvidenceFile.bytes),
    },
  };
}

export function normalizeKmsSignerProvenance(value) {
  assertCanonicalPlainDataGraph(value, { label: "KMS signer provenance" });
  const keys = ["kms_contract_id", "ca_pubkey", "env_encrypt_signer_k256", "valid_from", "valid_until"];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(keys.sort())
    || typeof value.env_encrypt_signer_k256 !== "string"
    || !/^0x0[23][0-9a-f]{64}$/.test(value.env_encrypt_signer_k256)
    || typeof value.valid_from !== "string"
    || typeof value.valid_until !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value.valid_from)
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value.valid_until)
    || !Number.isFinite(Date.parse(value.valid_from))
    || !Number.isFinite(Date.parse(value.valid_until))
    || new Date(Date.parse(value.valid_from)).toISOString().replace(".000Z", "Z")
      !== value.valid_from
    || new Date(Date.parse(value.valid_until)).toISOString().replace(".000Z", "Z")
      !== value.valid_until
    || Date.parse(value.valid_until) <= Date.parse(value.valid_from)) {
    throw new Error(
      "KMS signer provenance must contain only the reviewed contract identity, public keys, and canonical validity interval",
    );
  }
  // Reuse encoding validation only: this does not establish that the operator's
  // supplied public roots are authoritative. Fresh compatibility must match them.
  const keysOnly = normalizePhalaKmsContract({
    id: value.kms_contract_id,
    slug: "phala",
    label: null,
    contract_address: "phala",
    chain_id: 0,
    k256_pubkey: value.env_encrypt_signer_k256,
    ca_pubkey: value.ca_pubkey,
    node_count: 1,
  });
  if (keysOnly.ca_pubkey !== value.ca_pubkey
    || keysOnly.k256_pubkey !== value.env_encrypt_signer_k256) {
    throw new Error("KMS signer provenance public keys must use canonical encodings");
  }
  assertSecretFreePhalaAuthorityArtifact(value, "KMS signer provenance");
  return structuredClone(value);
}

function readKmsSignerProvenance(values) {
  const file = readCanonicalJson(
    values["--kms-signer-provenance"],
    "KMS signer provenance",
  );
  assertSecretFreePhalaAuthorityArtifact(file.value, "KMS signer provenance");
  const value = normalizeKmsSignerProvenance(file.value);
  return {
    ...file,
    value,
    sha256: rawSha256(file.bytes),
  };
}

export function recomputePhalaProductionTargetReviewInput(values, compatibility) {
  const reviewed = readValidatedTargetReviewDependencies(values);
  const signer = readKmsSignerProvenance(values);
  const input = createPhalaProductionTargetReviewInput({
    compatibilityReceipt: compatibility,
    releaseSha: reviewed.launch.release_sha,
    cvmLaunchIntentSha256: reviewed.launch_sha256,
    reviewEnvelopeSha256: reviewed.review_envelope_sha256,
    reviewEvidenceSha256: reviewed.review_evidence_sha256,
    kmsContractId: signer.value.kms_contract_id,
    kmsCaPubkey: signer.value.ca_pubkey,
    kmsSignerK256: signer.value.env_encrypt_signer_k256,
    kmsSignerProvenanceSha256: signer.sha256,
    kmsSignerValidFrom: signer.value.valid_from,
    kmsSignerValidUntil: signer.value.valid_until,
  });
  return {
    input,
    source_sha256: {
      ...reviewed.source_sha256,
      kms_signer_provenance: signer.sha256,
    },
  };
}

export function assertTargetReviewInputMatchesFreshSources(reviewed, recomputed) {
  if (canonicalPhalaProducerJsonText(reviewed)
      !== canonicalPhalaProducerJsonText(recomputed)) {
    throw new Error(
      "target review input does not equal the freshly revalidated source artifacts and signer provenance bytes",
    );
  }
  return reviewed;
}

function readAndRecomputeTargetReviewInput(values, compatibility) {
  const file = readCanonicalJson(values["--target-input"], "target review input");
  const reviewed = normalizePhalaProductionTargetReviewInput(file.value, {
    compatibilityReceipt: compatibility,
  });
  const recomputed = recomputePhalaProductionTargetReviewInput(values, compatibility);
  const normalizedText = canonicalPhalaProducerJsonText(reviewed);
  if (normalizedText !== file.bytes.toString("utf8")) {
    throw new Error(
      "target review input normalized bytes drifted before source replay",
    );
  }
  assertTargetReviewInputMatchesFreshSources(reviewed, recomputed.input);
  return {
    input: reviewed,
    source_sha256: {
      ...recomputed.source_sha256,
      target_review_input: rawSha256(file.bytes),
    },
  };
}

function normalizeCvmLaunchReviewReceiptForTarget(value, target) {
  const keys = [
    "schema", "status", "truthStatus", "subjectKind", "subjectSha256",
    "reviewEnvelopeSha256", "reviewEvidenceSha256", "checkpoint",
    "actionScopeCount", "reviewerDeclarationCount", "subjectSemanticValidation",
  ];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(keys.sort())) {
    throw new Error("CVM launch review receipt fields are invalid");
  }
  const expected = {
    schema: AUTHORITY_REVIEW_RECEIPT_SCHEMA,
    status: "valid",
    truthStatus:
      "canonical_subject_binding_and_review_declarations_validated_not_signatures_key_control_deployment_or_tdx",
    subjectKind: "cvm_launch_intent",
    subjectSha256: target.cvm_launch_intent_sha256,
    reviewEnvelopeSha256: target.review_envelope_sha256,
    reviewEvidenceSha256: target.review_evidence_sha256,
    checkpoint: REVIEW_SUBJECT_POLICY.cvm_launch_intent.checkpoint,
    actionScopeCount: CVM_LAUNCH_INTENT_ACTION_SCOPE.length,
    reviewerDeclarationCount: 2,
    subjectSemanticValidation: "cvm_launch_intent_validated",
  };
  if (JSON.stringify(value) !== JSON.stringify(expected)) {
    throw new Error("CVM launch review receipt does not bind the production target");
  }
  return expected;
}

export function publishCanonicalPhalaProducerArtifact({
  outputPath,
  text,
  beforePublish = null,
} = {}) {
  canonicalAbsolute(outputPath, "producer output", { existing: false });
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("producer output is not bounded canonical JSON");
  }
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_INPUT_BYTES
    || canonicalPhalaProducerJsonText(parsed) !== text) {
    throw new Error("producer output is not bounded canonical JSON");
  }
  const directory = canonicalAbsolute(path.dirname(outputPath), "producer output directory");
  const handle = pinPhalaPrivateDirectory(directory);
  try {
    assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
    if (beforePublish !== null) {
      if (typeof beforePublish !== "function") throw new Error("invalid producer test hook");
      beforePublish();
    }
    assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
    const identity = publishPhalaPinnedPrivateFile(
      handle,
      path.basename(outputPath),
      Buffer.from(text, "utf8"),
      { publishMode: "create", mode: 0o600, maximum: MAX_INPUT_BYTES },
    );
    assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
    return Object.freeze({
      artifact_sha256: identity.sha256,
      bytes: identity.size,
      status: "canonical_private_create_only_artifact_published",
    });
  } finally {
    closePhalaPinnedPrivateDirectory(handle);
  }
}

function readCompatibility(filePath) {
  const file = readCanonicalJson(filePath, "compatibility receipt");
  const value = normalizePhalaCompatibilityReceipt(file.value);
  if (canonicalPhalaCompatibilityReceiptText(value) !== file.bytes.toString("utf8")) {
    throw new Error("compatibility receipt normalized bytes drifted");
  }
  return value;
}

function readStaging(filePath, compatibility) {
  const file = readCanonicalJson(filePath, "staging receipt");
  const value = normalizePhalaSdkWireTransformStagingReceipt(file.value, {
    compatibilityReceipt: compatibility,
  });
  if (canonicalPhalaSdkWireTransformStagingReceiptText(value, {
    compatibilityReceipt: compatibility,
  }) !== file.bytes.toString("utf8")) {
    throw new Error("staging receipt normalized bytes drifted");
  }
  return value;
}

function readTarget(filePath, compatibility, staging) {
  const file = readCanonicalJson(filePath, "production target authority");
  const value = normalizePhalaProductionTargetAuthority(file.value, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
  if (canonicalPhalaProductionTargetAuthorityText(value, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  }) !== file.bytes.toString("utf8")) {
    throw new Error("production target authority normalized bytes drifted");
  }
  return value;
}

const OPAQUE_TRANSACTION_PLAN_STATUS =
  "opaque_bytes_hash_only_not_semantically_validated_or_transaction_authority";

export function normalizeOpaqueDeploymentTransactionPlan(value) {
  canonicalPhalaProducerJsonText(value);
  assertSecretFreePhalaAuthorityArtifact(value, "opaque deployment transaction plan");
  if (value?.status !== OPAQUE_TRANSACTION_PLAN_STATUS) {
    throw new Error(
      "opaque deployment transaction plan must self-identify as hash-only bytes without semantic or transaction authority",
    );
  }
  return structuredClone(value);
}

async function materializeBootstrapReviewInput(values, compatibility, staging, target) {
  const releaseDirectory = canonicalAbsolute(
    values["--release-directory"],
    "release directory",
  );
  const descriptorSetReceipt = await validateCanonicalGeneratedCvmDescriptorSet({
    releaseDirectory,
    expectedReleaseSha: target.release_sha,
  });
  const deploymentFile = readStableBytes(
    values["--deployment-intent"],
    "deployment intent",
  );
  const deployment = requireValid(
    parseDeploymentIntentCoreText(deploymentFile.toString("utf8")),
    "deployment intent",
  );
  const launchFile = readStableBytes(
    values["--cvm-launch-intent"],
    "CVM launch intent",
  );
  const launch = parseCvmLaunchIntentCoreText(launchFile.toString("utf8"));
  const launchSha256 = `sha256:${cvmLaunchIntentCoreDigest(launch)}`;
  if (canonicalCvmLaunchIntentCoreArtifactText(launch) !== launchFile.toString("utf8")
    || launchSha256 !== target.cvm_launch_intent_sha256
    || launch.release_sha !== target.release_sha
    || launch.deployment_intent_sha256
      !== deployment.receipt.deploymentIntentSha256) {
    throw new Error("bootstrap CVM launch and deployment intent lineage drifted");
  }
  const freshFile = readStableJson(
    values["--fresh-contract-deployment-receipt"],
    "fresh-contract deployment receipt",
  );
  const freshPins = {
    expectedDeploymentIntentSha256:
      deployment.receipt.deploymentIntentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      deployment.intent.release.reviewerAuthorityGenesisAcceptanceSha256,
    expectedTinkerAccountBindingCeremonyReceiptSha256:
      freshFile.value?.tinker_account_binding_ceremony_receipt_sha256,
  };
  const freshReceipt = normalizeFreshContractDeploymentReceipt(
    freshFile.value,
    freshPins,
  );
  const freshReceiptSha256 = `sha256:${freshContractDeploymentReceiptDigest(
    freshReceipt,
    freshPins,
  )}`;
  if (canonicalFreshContractDeploymentReceiptText(freshReceipt, freshPins)
      !== freshFile.bytes.toString("utf8")
    || freshReceiptSha256 !== launch.contract_deployment_receipt_sha256) {
    throw new Error("fresh-contract deployment receipt drifted from CVM launch authority");
  }
  const sigstoreFile = readStableJson(
    values["--image-release-sigstore-verification-receipt"],
    "image release Sigstore verification receipt",
  );
  const sigstore = normalizeReleaseManifestSigstoreVerificationReceipt(
    sigstoreFile.value,
  );
  if (canonicalReleaseManifestSigstoreVerificationReceiptText(sigstore)
      !== sigstoreFile.bytes.toString("utf8")
    || sigstore.release_sha !== target.release_sha
    || sigstore.release_manifest_sha256 !== launch.image_release_manifest_sha256) {
    throw new Error("image release Sigstore receipt drifted from launch authority");
  }
  const qvlFile = readStableJson(
    values["--qvl-measurement-policy-set"],
    "QVL measurement policy set",
  );
  const qvlPolicy = normalizePhalaQvlMeasurementPolicySet(qvlFile.value);
  if (canonicalPhalaQvlMeasurementPolicySetText(qvlPolicy)
      !== qvlFile.bytes.toString("utf8")
    || qvlPolicy.deployment_intent_sha256
      !== deployment.receipt.deploymentIntentSha256) {
    throw new Error("QVL measurement policy set drifted from deployment authority");
  }
  const reviewReceiptFile = readStableJson(
    values["--cvm-launch-review-receipt"],
    "CVM launch review receipt",
  );
  const reviewReceipt = normalizeCvmLaunchReviewReceiptForTarget(
    reviewReceiptFile.value,
    target,
  );
  if (`${JSON.stringify(reviewReceipt, null, 2)}\n`
      !== reviewReceiptFile.bytes.toString("utf8")) {
    throw new Error("CVM launch review receipt is not authoritative canonical bytes");
  }
  const transactionPlanFile = readCanonicalJson(
    values["--deployment-transaction-plan"],
    "opaque deployment transaction plan",
  );
  normalizeOpaqueDeploymentTransactionPlan(transactionPlanFile.value);
  if (descriptorSetReceipt.topology_sha256 !== launch.topology_sha256
    || descriptorSetReceipt.image_manifest_sha256
      !== launch.image_release_manifest_sha256
    || launch.descriptors.some(({ trust_domain: domain, descriptor_sha256: digestValue }) => (
      descriptorSetReceipt.descriptor_sha256_by_domain[domain] !== digestValue
    ))) {
    throw new Error("generated descriptor set drifted from CVM launch authority");
  }
  return createBootstrapPublicEnvironmentReviewInput({
    descriptorSetReceipt,
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    productionTargetAuthority: target,
    lineage: {
      deployment_intent_sha256: deployment.receipt.deploymentIntentSha256,
      deployment_transaction_plan_sha256: rawSha256(transactionPlanFile.bytes),
      fresh_contract_deployment_receipt_sha256: freshReceiptSha256,
      image_release_sigstore_verification_receipt_sha256:
        releaseManifestSigstoreVerificationReceiptSha256(sigstore),
      cvm_launch_intent_sha256: launchSha256,
      cvm_launch_review_receipt_sha256: rawSha256(reviewReceiptFile.bytes),
      qvl_measurement_policy_set_sha256:
        phalaQvlMeasurementPolicySetSha256(qvlPolicy),
    },
  });
}

export function assertBootstrapReviewInputMatchesFreshSources(reviewed, pristine) {
  if (!reviewed || typeof reviewed !== "object" || Array.isArray(reviewed)
    || !Array.isArray(reviewed.domains)
    || reviewed.domains.length !== pristine.domains.length) {
    throw new Error("bootstrap review input is not the exact reviewed structure");
  }
  const projected = structuredClone(reviewed);
  for (let index = 0; index < pristine.domains.length; index += 1) {
    const candidate = projected.domains[index];
    const expected = pristine.domains[index];
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)
      || JSON.stringify(Object.keys(candidate).sort())
        !== JSON.stringify(["domain", "descriptor_sha256", "values"].sort())
      || candidate.domain !== expected.domain
      || candidate.descriptor_sha256 !== expected.descriptor_sha256
      || !candidate.values || typeof candidate.values !== "object"
      || Array.isArray(candidate.values)
      || JSON.stringify(Object.keys(candidate.values).sort())
        !== JSON.stringify(Object.keys(expected.values).sort())) {
      throw new Error(
        "bootstrap review input domain, descriptor, or public-value keys drifted from fresh sources",
      );
    }
    candidate.values = structuredClone(expected.values);
  }
  if (canonicalPhalaProducerJsonText(projected)
      !== canonicalPhalaProducerJsonText(pristine)) {
    throw new Error(
      "bootstrap review input immutable lineage, target, topology, manifest, or descriptor bindings drifted from fresh sources",
    );
  }
}

async function execute(parsed) {
  if (parsed.command === "help") return { help: true };
  assertSafePhalaSdkProcessEnvironment();
  const values = parsed.values;
  let artifact;
  let text;
  if (parsed.command === "observe-compatibility") {
    artifact = await observePinnedPhalaCompatibility();
    text = canonicalPhalaCompatibilityReceiptText(artifact);
  } else if (parsed.command === "init-kms-signer-provenance") {
    artifact = normalizeKmsSignerProvenance({
      kms_contract_id: values["--kms-contract-id"],
      ca_pubkey: values["--ca-pubkey"],
      env_encrypt_signer_k256: values["--env-encrypt-signer-k256"],
      valid_from: values["--valid-from"],
      valid_until: values["--valid-until"],
    });
    text = canonicalPhalaProducerJsonText(artifact);
  } else if (parsed.command === "init-target-input") {
    const compatibility = readCompatibility(values["--compatibility"]);
    artifact = recomputePhalaProductionTargetReviewInput(values, compatibility).input;
    text = canonicalPhalaProducerJsonText(artifact);
  } else if (parsed.command === "observe-staging") {
    if (values["--confirm-dedicated-staging-workspace"] !== "true") {
      throw new Error("staging observation requires explicit dedicated-workspace designation");
    }
    const compatibility = readCompatibility(values["--compatibility"]);
    const recomputed = readAndRecomputeTargetReviewInput(values, compatibility);
    const targetInput = recomputed.input;
    const releaseDirectory = canonicalAbsolute(
      values["--release-directory"],
      "release directory",
    );
    const runtimeAuthority = await createFreshCvmDescriptorRuntimeAuthority({
      releaseDirectory,
      expectedReleaseSha: targetInput.release_sha,
    });
    const descriptorMaterials = await readFreshCvmDescriptorRuntimeMaterials({
      authority: runtimeAuthority,
      releaseDirectory,
    });
    const sourceManifest = {
      target_sources: recomputed.source_sha256,
      descriptor_materials: descriptorMaterials.map((material) => ({
        domain: material.domain,
        descriptor_material_sha256: rawSha256(Buffer.from(
          canonicalPhalaProducerJsonText({
            domain: material.domain,
            docker_compose_file: material.docker_compose_file,
            allowed_environment_keys: material.allowed_environment_keys,
          }),
          "utf8",
        )),
      })),
    };
    const stagingSession = await createPinnedPhalaPreProvisionStagingSession({
      compatibilityReceipt: compatibility,
      outputPath: values["--out"],
      releaseSha: targetInput.release_sha,
      targetReviewInputSha256: phalaProductionTargetReviewInputDigest(
        targetInput,
        { compatibilityReceipt: compatibility },
      ),
      sourceManifest,
      operatorAssertedDedicatedWorkspace: true,
    });
    artifact = await capturePhalaSdkWireTransformStagingReceipt({
      compatibilityReceipt: compatibility,
      targetReviewInput: targetInput,
      descriptorMaterials,
      stagingSession,
    });
    text = canonicalPhalaSdkWireTransformStagingReceiptText(artifact, {
      compatibilityReceipt: compatibility,
    });
    return {
      publication: publishPinnedPhalaPreProvisionStagingReceipt({
        stagingSession,
        canonicalReceiptText: text,
      }),
    };
  } else if (parsed.command === "finalize-target") {
    const compatibility = readCompatibility(values["--compatibility"]);
    const staging = readStaging(values["--staging"], compatibility);
    const targetInput = readAndRecomputeTargetReviewInput(values, compatibility).input;
    artifact = finalizePhalaProductionTargetAuthority({
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
      targetReviewInput: targetInput,
    });
    text = canonicalPhalaProductionTargetAuthorityText(artifact, {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    });
  } else if (parsed.command === "init-bootstrap-input") {
    const compatibility = readCompatibility(values["--compatibility"]);
    const staging = readStaging(values["--staging"], compatibility);
    const target = readTarget(values["--target"], compatibility, staging);
    artifact = await materializeBootstrapReviewInput(
      values,
      compatibility,
      staging,
      target,
    );
    text = canonicalPhalaProducerJsonText(artifact);
  } else if (parsed.command === "finalize-bootstrap") {
    const compatibility = readCompatibility(values["--compatibility"]);
    const staging = readStaging(values["--staging"], compatibility);
    const target = readTarget(values["--target"], compatibility, staging);
    const lifetimeSeconds = Number(values["--lifetime-seconds"]);
    const reviewed = readCanonicalJson(
      values["--bootstrap-input"],
      "bootstrap public-environment review input",
    ).value;
    const pristine = await materializeBootstrapReviewInput(
      values,
      compatibility,
      staging,
      target,
    );
    assertBootstrapReviewInputMatchesFreshSources(reviewed, pristine);
    artifact = finalizeBootstrapPublicEnvironmentAuthority({
      reviewInput: reviewed,
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
      productionTargetAuthority: target,
      lifetimeSeconds,
    });
    text = canonicalBootstrapPublicEnvironmentAuthorityText(artifact);
  }
  const publication = publishCanonicalPhalaProducerArtifact({
    outputPath: values["--out"],
    text,
  });
  return { publication };
}

export async function runPhalaPreProvisionAuthorityProducer(argv, {
  stdout = (text) => process.stdout.write(text),
} = {}) {
  if (Array.isArray(argv) && argv.length > 0
    && !["help", "--help", "-h"].includes(argv[0])) {
    assertSafePhalaSdkProcessEnvironment();
  }
  const parsed = parsePhalaPreProvisionAuthorityProducerArgs(argv);
  const result = await execute(parsed);
  if (result.help) {
    stdout(`${PHALA_PRE_PROVISION_AUTHORITY_PRODUCER_USAGE}\n`);
    return;
  }
  stdout(canonicalPhalaProducerJsonText(result.publication));
}

const isMain = process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const requestedCommand = process.argv[2] ?? "help";
  const command = Object.hasOwn(COMMAND_FLAGS, requestedCommand)
    ? requestedCommand
    : "unknown-command";
  runPhalaPreProvisionAuthorityProducer(process.argv.slice(2)).catch(() => {
    process.stderr.write(`phala_pre_provision_authority_producer_failed:${command}\n`);
    process.exitCode = 1;
  });
}
