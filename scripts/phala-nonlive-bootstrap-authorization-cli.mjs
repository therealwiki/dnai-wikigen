#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
  canonicalArtifactSha256,
  canonicalArtifactText,
  parseDeploymentIntentCoreText,
} from "./operator-policy-packet-core.mjs";
import {
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
  bootstrapPublicEnvironmentAuthorityDigest,
  canonicalBootstrapPublicEnvironmentAuthorityText,
  normalizeBootstrapPublicEnvironmentAuthority,
} from "./phala-production-environment-authority.mjs";
import {
  PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH,
  PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE,
  canonicalPhalaNonLiveBootstrapAuthorizationText,
  createPhalaNonLiveBootstrapSigningPayload,
  phalaNonLiveBootstrapAuthorizationId,
  phalaNonLiveBootstrapSigningDigest,
  phalaNonLiveBootstrapSigningMessage,
  readAndVerifyPhalaNonLiveBootstrapAuthorization,
} from "./phala-nonlive-bootstrap-authorization.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  canonicalLowSEip191Signature,
} from "./release-authority-signature-verifier.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation,
  canonicalReleaseReviewerAuthorityGenesisArtifactText,
  releaseReviewerAuthorityGenesisSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime,
  canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  durablyPublishJson,
  durablyRemoveJson,
} from "./durable-json-write.mjs";
import {
  PHALA_RELEASE_MANIFEST_SIGSTORE_VERIFICATION_MISSING,
  PHALA_REVIEWER_GENESIS_ANCHOR_MISSING,
} from "./phala-production-execution-policy.mjs";

export const PHALA_NONLIVE_BOOTSTRAP_EXTERNAL_SIGNATURES_SCHEMA =
  "dnai.phala-nonlive-bootstrap-external-signatures.v1";
export const PHALA_NONLIVE_BOOTSTRAP_SIGNING_DIAGNOSTIC_SCHEMA =
  "dnai.phala-nonlive-bootstrap-signing-diagnostic.v1";
export const PHALA_NONLIVE_BOOTSTRAP_PUBLICATION_RECEIPT_SCHEMA =
  "dnai.phala-nonlive-bootstrap-local-publication.v1";
export const PHALA_NONLIVE_BOOTSTRAP_STABLE_VERIFICATION_RECEIPT_SCHEMA =
  "dnai.phala-nonlive-bootstrap-stable-verification-receipt.v1";
export const PHALA_NONLIVE_BOOTSTRAP_LOCAL_PUBLICATION_BLOCKER_CODES =
  Object.freeze([
    PHALA_RELEASE_MANIFEST_SIGSTORE_VERIFICATION_MISSING,
    PHALA_REVIEWER_GENESIS_ANCHOR_MISSING,
    "full_launch_checkpoint_target_descriptor_contract_and_sigstore_verification_not_performed",
  ]);

const OPERATION_ERROR_SCHEMA =
  "dnai.phala-nonlive-bootstrap-authorization-operation-error.v1";
const MAX_INPUT_BYTES = 4 * 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;

const COMMON_FLAGS = Object.freeze([
  "--batch-id",
  "--bootstrap-authority",
  "--deployment-intent",
  "--expires-at",
  "--issued-at",
  "--reviewer-genesis-acceptance",
  "--reviewer-genesis",
]);
const CREATE_ONLY_FLAGS = Object.freeze([
  "--authorization-out",
  "--now",
  "--receipt-out",
  "--signatures",
]);
const FORBIDDEN_SIGNER_FLAGS = new Set([
  "--account",
  "--env",
  "--keystore",
  "--key",
  "--mnemonic",
  "--password",
  "--phala-api-key",
  "--private-key",
  "--raw-key",
  "--rpc-url",
  "--signer",
  "--signer-command",
]);

export const PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_CLI_USAGE = `Usage:
  node scripts/phala-nonlive-bootstrap-authorization-cli.mjs diagnose \\
    --bootstrap-authority FILE --deployment-intent FILE --reviewer-genesis FILE \\
    --reviewer-genesis-acceptance FILE \\
    --batch-id SHA256 --issued-at UTC_SECOND --expires-at UTC_SECOND

  node scripts/phala-nonlive-bootstrap-authorization-cli.mjs create-new \\
    --bootstrap-authority FILE --deployment-intent FILE --reviewer-genesis FILE \\
    --batch-id SHA256 --issued-at UTC_SECOND --expires-at UTC_SECOND \\
    --reviewer-genesis-acceptance FILE \\
    --signatures FILE --authorization-out FILE --receipt-out FILE [--now UTC_SECOND]

diagnose emits the exact canonical signing payload, EIP-191 personal-sign
message, and signing digest. It performs no writes, signing, network request,
Phala action, or live activation.

create-new accepts a canonical external-signature envelope containing exactly
two externally produced low-s EIP-191 signatures. It never accepts a private
key, raw key, mnemonic, keystore, Foundry account, signer command, RPC URL, or
Phala credential. It verifies signatures with the release-pinned verifier,
creates new files without replacement, and writes a canonical non-live
authorization plus its verification receipt. It cannot authorize late secrets,
governance ceremony actions, live traffic, or Cloudflare deployment.`;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    throw new Error(`${label} fields do not match the exact schema`);
  }
  return value;
}

function exactTimestamp(value, label) {
  const parsedMs = typeof value === "string" && ISO_SECOND.test(value)
    ? Date.parse(value)
    : Number.NaN;
  if (!Number.isFinite(parsedMs)
    || new Date(parsedMs).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  return value;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function scrubErrorMessage(error) {
  return String(error?.message || "operation failed")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/0x[0-9a-fA-F]{64,}/g, "[redacted-hex]")
    .slice(0, 400);
}

function operationError(command, error) {
  return canonicalArtifactText({
    schema: OPERATION_ERROR_SCHEMA,
    status: "operation_failed",
    truth_status:
      "local_create_only_output_state_may_require_exact_path_inspection_no_phala_mutation_or_live_authority_created",
    command: typeof command === "string" && command ? command : "unknown",
    message: scrubErrorMessage(error),
    network_request_performed: false,
    phala_mutation_performed: false,
    signer_subprocess_invoked: false,
  });
}

function flagName(argument) {
  return String(argument).split("=", 1)[0];
}

export function parsePhalaNonLiveBootstrapAuthorizationCliArgs(argv) {
  const [rawCommand, ...rest] = argv;
  const command = rawCommand === "--help" || rawCommand === "-h"
    ? "help"
    : rawCommand;
  if (!command) throw new Error("a command is required; use --help");
  if (!["diagnose", "create-new", "help"].includes(command)) {
    throw new Error("unsupported command; use --help");
  }
  const values = { command };
  const seen = new Set();
  const allowed = new Set(command === "create-new"
    ? [...COMMON_FLAGS, ...CREATE_ONLY_FLAGS]
    : COMMON_FLAGS);
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === "--help" || argument === "-h") {
      if (rest.length !== 1) throw new Error("--help cannot be combined with operation flags");
      return { command: "help" };
    }
    const flag = flagName(argument);
    if (FORBIDDEN_SIGNER_FLAGS.has(flag)) {
      throw new Error(`forbidden signer or credential flag: ${flag}`);
    }
    if (argument.includes("=") || !allowed.has(argument)) {
      throw new Error(`unsupported argument: ${flag}; use --help`);
    }
    if (seen.has(argument)) throw new Error(`duplicate argument: ${argument}`);
    seen.add(argument);
    const next = rest[index + 1];
    if (next === undefined || next.startsWith("-")) {
      throw new Error(`missing value for ${argument}`);
    }
    values[argument.slice(2).replaceAll("-", "_")] = next;
    index += 1;
  }
  if (command === "help") {
    if (rest.length) throw new Error("help does not accept operation flags");
    return values;
  }
  for (const flag of COMMON_FLAGS) {
    const name = flag.slice(2).replaceAll("-", "_");
    if (!values[name]) throw new Error(`required argument is missing: ${flag}`);
  }
  if (command === "create-new") {
    for (const flag of ["--signatures", "--authorization-out", "--receipt-out"]) {
      const name = flag.slice(2).replaceAll("-", "_");
      if (!values[name]) throw new Error(`required argument is missing: ${flag}`);
    }
  }
  exactTimestamp(values.issued_at, "bootstrap issued_at");
  exactTimestamp(values.expires_at, "bootstrap expires_at");
  if (values.now !== undefined) {
    exactTimestamp(values.now, "verification now");
  }
  return values;
}

function canonicalExistingPath(input, label) {
  if (typeof input !== "string" || input.includes("\0")) {
    throw new Error(`${label} path is required`);
  }
  const resolved = path.resolve(input);
  if (fs.realpathSync.native(resolved) !== resolved) {
    throw new Error(`${label} path must be canonical and symlink-free`);
  }
  return resolved;
}

function stableCanonicalJson(input, label) {
  const filePath = canonicalExistingPath(input, label);
  const before = fs.lstatSync(filePath);
  const expectedUid = typeof process.geteuid === "function"
    ? process.geteuid()
    : before.uid;
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
    || before.uid !== expectedUid || (before.mode & 0o022) !== 0
    || before.size < 2 || before.size > MAX_INPUT_BYTES) {
    throw new Error(
      `${label} must be an operator-owned bounded single-link non-writable regular file`,
    );
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd);
    if (opened.dev !== before.dev || opened.ino !== before.ino
      || opened.size !== before.size) {
      throw new Error(`${label} changed while opening`);
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) {
        throw new Error(`${label} ended during its stable read`);
      }
      offset += count;
    }
    const after = fs.fstatSync(fd);
    const finalPathStat = fs.lstatSync(filePath);
    if (after.dev !== opened.dev || after.ino !== opened.ino
      || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs
      || after.ctimeMs !== opened.ctimeMs
      || finalPathStat.dev !== opened.dev || finalPathStat.ino !== opened.ino
      || fs.realpathSync.native(filePath) !== filePath) {
      throw new Error(`${label} changed during its stable read`);
    }
    const text = bytes.toString("utf8");
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error(`${label} is not valid JSON`);
    }
    if (canonicalArtifactText(value) !== text) {
      throw new Error(
        `${label} must use canonical sorted two-space JSON with one trailing newline`,
      );
    }
    return Object.freeze({ bytes, filePath, sha256: sha256Bytes(bytes), text, value });
  } finally {
    fs.closeSync(fd);
  }
}

function readAuthorityInputs(args) {
  const bootstrapFile = stableCanonicalJson(
    args.bootstrap_authority,
    "bootstrap public environment authority",
  );
  const bootstrap = normalizeBootstrapPublicEnvironmentAuthority(bootstrapFile.value);
  if (bootstrapFile.value.schema !== PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA
    || canonicalBootstrapPublicEnvironmentAuthorityText(bootstrap) !== bootstrapFile.text) {
    throw new Error("bootstrap public environment authority is not canonical authority");
  }

  const deploymentIntentFile = stableCanonicalJson(
    args.deployment_intent,
    "deployment intent",
  );
  const parsedIntent = parseDeploymentIntentCoreText(deploymentIntentFile.text);
  if (!parsedIntent.ok) {
    throw new Error("deployment intent is not canonical deployment-intent v6 authority");
  }
  const deploymentIntentSha256 = canonicalArtifactSha256(parsedIntent.intent);
  if (deploymentIntentSha256 !== bootstrap.deployment_intent_sha256
    || parsedIntent.intent.release.releaseSha !== bootstrap.release_sha) {
    throw new Error("deployment intent does not match the bootstrap authority release");
  }

  const genesisFile = stableCanonicalJson(
    args.reviewer_genesis,
    "reviewer authority genesis",
  );
  const deploymentRoleAddresses = [...new Set([
    parsedIntent.intent.deploymentControl.operatorAddress,
    parsedIntent.intent.staticContractInputs.computeCreditVault.developer,
  ])].sort();
  const deploymentRoleControllerIds = [
    parsedIntent.intent.deploymentControl.controllerId,
  ];
  const genesisOptions = {
    deploymentRoleAddresses,
    deploymentRoleControllerIds,
  };
  const genesis = assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation(
    genesisFile.value,
    genesisOptions,
  );
  if (genesis.schema !== RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA
    || canonicalReleaseReviewerAuthorityGenesisArtifactText(
      genesis,
      genesisOptions,
    )
      !== genesisFile.text) {
    throw new Error("reviewer authority genesis is not canonical authority");
  }
  const genesisSha256 = releaseReviewerAuthorityGenesisSha256(
    genesis,
    genesisOptions,
  );
  const genesisAcceptanceFile = stableCanonicalJson(
    args.reviewer_genesis_acceptance,
    "reviewer authority genesis acceptance",
  );
  const issuedAt = exactTimestamp(args.issued_at, "bootstrap issued_at");
  const acceptanceOptions = {
    reviewerGenesis: genesis,
    ...genesisOptions,
  };
  const genesisAcceptance =
    assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime(
      genesisAcceptanceFile.value,
      {
        ...acceptanceOptions,
        now: issuedAt,
        expectedCurrentStatusEpoch:
          parsedIntent.intent.release.reviewerAuthorityCurrentStatusEpoch,
        expectedCurrentStatusSha256:
          parsedIntent.intent.release.reviewerAuthorityCurrentStatusSha256,
      },
    );
  if (genesisAcceptance.schema
      !== RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA
    || canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
      genesisAcceptance,
      acceptanceOptions,
    ) !== genesisAcceptanceFile.text) {
    throw new Error("reviewer authority genesis acceptance is not canonical authority");
  }
  const genesisAcceptanceSha256 =
    releaseReviewerAuthorityGenesisAcceptanceSha256(
      genesisAcceptance,
      acceptanceOptions,
    );
  if (genesisAcceptanceSha256
      !== parsedIntent.intent.release.reviewerAuthorityGenesisAcceptanceSha256
    || genesisAcceptance.reviewer_authority_genesis_sha256 !== genesisSha256
    || genesis.release_sha !== bootstrap.release_sha
    || genesis.chain_id !== 84_532
    || genesisAcceptance.reviewer_authority_current_status.epoch
      !== parsedIntent.intent.release.reviewerAuthorityCurrentStatusEpoch
    || genesisAcceptance.reviewer_authority_current_status_sha256
      !== parsedIntent.intent.release.reviewerAuthorityCurrentStatusSha256) {
    throw new Error(
      "reviewer identities are not transitively precommitted by deployment intent v6",
    );
  }
  const activeReviewers =
    genesisAcceptance.reviewer_authority_current_status.active_reviewers;
  if (activeReviewers.length !== 2) {
    throw new Error(
      "non-live bootstrap v1 requires exactly two currently active transitively precommitted reviewers",
    );
  }
  return Object.freeze({
    bootstrap,
    bootstrapFile,
    deploymentIntentFile,
    deploymentIntentSha256,
    genesis,
    genesisAcceptance,
    genesisAcceptanceFile,
    genesisAcceptanceSha256,
    activeReviewers,
    genesisFile,
    genesisSha256,
  });
}

function createSigningDiagnostic(args) {
  const authority = readAuthorityInputs(args);
  const bootstrapDigest = bootstrapPublicEnvironmentAuthorityDigest(
    authority.bootstrap,
  );
  const payload = createPhalaNonLiveBootstrapSigningPayload({
    schema: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA,
    status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS,
    truth_status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH,
    authorization_id: phalaNonLiveBootstrapAuthorizationId({
      releaseSha: authority.bootstrap.release_sha,
      batchId: exactSha256(args.batch_id, "bootstrap batch_id"),
      bootstrapPublicEnvironmentAuthoritySha256: bootstrapDigest,
    }),
    chain_id: 84_532,
    release_sha: authority.bootstrap.release_sha,
    batch_id: args.batch_id,
    bootstrap_public_environment_authority_sha256: bootstrapDigest,
    deployment_intent_sha256: authority.bootstrap.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      authority.bootstrap.fresh_contract_deployment_receipt_sha256,
    image_release_sigstore_verification_receipt_sha256:
      authority.bootstrap.image_release_sigstore_verification_receipt_sha256,
    cvm_launch_intent_sha256: authority.bootstrap.cvm_launch_intent_sha256,
    cvm_launch_review_receipt_sha256:
      authority.bootstrap.cvm_launch_review_receipt_sha256,
    production_target_authority_sha256:
      authority.bootstrap.production_target_authority_sha256,
    sdk_wire_transform_staging_receipt_sha256:
      authority.bootstrap.sdk_wire_transform_staging_receipt_sha256,
    qvl_measurement_policy_set_sha256:
      authority.bootstrap.qvl_measurement_policy_set_sha256,
    action_scope: [...PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE],
    forbidden_scope: [...PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE],
    issued_at: exactTimestamp(args.issued_at, "bootstrap issued_at"),
    expires_at: exactTimestamp(args.expires_at, "bootstrap expires_at"),
    reviewer_root_hash:
      authority.genesisAcceptance.reviewer_authority_current_status.reviewer_root_hash,
    reviewer_set_sha256:
      authority.genesisAcceptance.reviewer_authority_current_status.reviewer_set_sha256,
    reviewers: authority.activeReviewers.map((entry) => ({ ...entry })),
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
  }, { bootstrapAuthority: authority.bootstrap });
  const digest = phalaNonLiveBootstrapSigningDigest(payload, {
    bootstrapAuthority: authority.bootstrap,
  });
  const message = phalaNonLiveBootstrapSigningMessage(payload, {
    bootstrapAuthority: authority.bootstrap,
  });
  return Object.freeze({
    authority,
    payload,
    diagnostic: Object.freeze({
      schema: PHALA_NONLIVE_BOOTSTRAP_SIGNING_DIAGNOSTIC_SCHEMA,
      status: "ready_for_external_eip191_personal_signatures",
      truth_status:
        "canonical_payload_and_transitive_reviewer_derivation_only_not_full_target_descriptor_contract_sigstore_phala_mutation_tdx_or_live_authority",
      authorization_id: payload.authorization_id,
      batch_id: payload.batch_id,
      bootstrap_public_environment_authority_sha256:
        payload.bootstrap_public_environment_authority_sha256,
      deployment_intent_sha256: authority.deploymentIntentSha256,
      reviewer_authority_genesis_sha256: authority.genesisSha256,
      reviewer_authority_genesis_acceptance_sha256:
        authority.genesisAcceptanceSha256,
      bootstrap_evidence: {
        image_release_manifest_sha256:
          authority.bootstrap.image_release_manifest_sha256,
        image_release_sigstore_verification_receipt_sha256:
          authority.bootstrap.image_release_sigstore_verification_receipt_sha256,
      },
      eip191: {
        message,
        message_encoding: "utf8_eip191_personal_sign",
        signed_payload_sha256: digest,
        signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
        signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
      },
      signing_payload: payload,
      operator_controls: {
        externally_supplied_signature_count_required: 2,
        foundry_account_flag_accepted: false,
        private_or_raw_key_input_accepted: false,
        pinned_signature_verification_subprocess_invoked: true,
        signer_subprocess_invoked: false,
        verification_subprocess_required_on_create: true,
      },
      blocker_codes: [
        ...PHALA_NONLIVE_BOOTSTRAP_LOCAL_PUBLICATION_BLOCKER_CODES,
      ],
      forbidden_scope: [...PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE],
      network_request_performed: false,
      phala_mutation_performed: false,
      production_mutation_ready: false,
      live_traffic_authorized: false,
    }),
  });
}

function normalizeExternalSignatures(file, expected) {
  const envelope = exactRecord(file.value, [
    "schema",
    "signature_scheme",
    "signed_payload_sha256",
    "signatures",
  ], "external bootstrap signature envelope");
  if (envelope.schema !== PHALA_NONLIVE_BOOTSTRAP_EXTERNAL_SIGNATURES_SCHEMA
    || envelope.signature_scheme !== PINNED_EIP191_SIGNATURE_SCHEME
    || envelope.signed_payload_sha256 !== expected.signedPayloadSha256
    || !Array.isArray(envelope.signatures)
    || envelope.signatures.length !== 2) {
    throw new Error(
      "external signatures do not bind this exact non-live bootstrap signing payload",
    );
  }
  return envelope.signatures.map((raw, index) => {
    const signature = exactRecord(raw, [
      "address", "controller_id", "signature",
    ], `external bootstrap signature ${index}`);
    const reviewer = expected.reviewers[index];
    if (!ADDRESS.test(signature.address)
      || signature.address !== reviewer.address
      || signature.controller_id !== reviewer.controller_id) {
      throw new Error(
        "external signature identities must equal the sorted transitive reviewer identities",
      );
    }
    return {
      address: signature.address,
      controller_id: signature.controller_id,
      signature: canonicalLowSEip191Signature(
        signature.signature,
        `external bootstrap signature ${index}`,
      ),
    };
  });
}

function canonicalNewOutputPath(input, label) {
  if (typeof input !== "string" || input.includes("\0")) {
    throw new Error(`${label} path is required`);
  }
  const resolved = path.resolve(input);
  const directory = path.dirname(resolved);
  if (fs.realpathSync.native(directory) !== directory) {
    throw new Error(`${label} directory must be canonical and symlink-free`);
  }
  try {
    fs.lstatSync(resolved);
    throw new Error(`${label} already exists; create-new never replaces authority`);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  return resolved;
}

function writePrivateTemporaryJson(directory, stem, text) {
  const filePath = path.join(
    directory,
    `.${stem}.${process.pid}.${randomBytes(16).toString("hex")}.json`,
  );
  let fd;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
      0o600,
    );
    const bytes = Buffer.from(text, "utf8");
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.writeSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) {
        throw new Error("temporary authority write made no forward progress");
      }
      offset += count;
    }
    fs.fsyncSync(fd);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size !== bytes.length
      || (stat.mode & 0o777) !== 0o600) {
      throw new Error("temporary authority file was not written exactly");
    }
    fs.closeSync(fd);
    fd = undefined;
    if (fs.realpathSync.native(filePath) !== filePath) {
      throw new Error("temporary authority path became an alias");
    }
    return filePath;
  } catch (error) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* preserve original error */ }
    }
    try { fs.unlinkSync(filePath); } catch { /* source may not exist */ }
    throw error;
  }
}

function safeRemoveTemporary(filePath) {
  if (!filePath) return;
  try {
    const stat = fs.lstatSync(filePath);
    if (!stat.isSymbolicLink() && stat.isFile() && stat.nlink === 1
      && (typeof process.geteuid !== "function" || stat.uid === process.geteuid())) {
      fs.unlinkSync(filePath);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") {
      // A private-directory orphan is safer than unlinking a changed path.
    }
  }
}

function verificationOptions(args, authorizationPath, nowMs) {
  return {
    authorizationPath,
    bootstrapAuthorityPath: path.resolve(args.bootstrap_authority),
    deploymentIntentPath: path.resolve(args.deployment_intent),
    reviewerAuthorityGenesisPath: path.resolve(args.reviewer_genesis),
    reviewerAuthorityGenesisAcceptancePath:
      path.resolve(args.reviewer_genesis_acceptance),
    nowMs,
  };
}

function createNewAuthorization(args) {
  const built = createSigningDiagnostic(args);
  const signedPayloadSha256 = built.diagnostic.eip191.signed_payload_sha256;
  const signaturesFile = stableCanonicalJson(
    args.signatures,
    "external bootstrap signatures",
  );
  const signatures = normalizeExternalSignatures(signaturesFile, {
    reviewers: built.payload.reviewers,
    signedPayloadSha256,
  });
  const authorization = {
    ...built.payload,
    signed_payload_sha256: signedPayloadSha256,
    signatures,
  };
  const authorizationText = canonicalPhalaNonLiveBootstrapAuthorizationText(
    authorization,
    { bootstrapAuthority: built.authority.bootstrap },
  );
  const authorizationOutput = canonicalNewOutputPath(
    args.authorization_out,
    "authorization output",
  );
  const receiptOutput = canonicalNewOutputPath(args.receipt_out, "receipt output");
  if (authorizationOutput === receiptOutput) {
    throw new Error("authorization and receipt output paths must be distinct");
  }
  const nowMs = args.now === undefined
    ? Date.now()
    : Date.parse(exactTimestamp(args.now, "verification now"));
  let authorizationSource;
  let receiptSource;
  let authorizationPublished = false;
  try {
    authorizationSource = writePrivateTemporaryJson(
      path.dirname(authorizationOutput),
      "phala-bootstrap-authorization-source",
      authorizationText,
    );
    // Verify the exact candidate bytes before any durable output publication.
    readAndVerifyPhalaNonLiveBootstrapAuthorization(
      verificationOptions(args, authorizationSource, nowMs),
    );
    durablyPublishJson({
      sourcePath: authorizationSource,
      outputPath: authorizationOutput,
      publishMode: "create",
      fileMode: 0o600,
    });
    authorizationPublished = true;

    // Re-read and re-verify the published inode through the stable-file API.
    const verified = readAndVerifyPhalaNonLiveBootstrapAuthorization(
      verificationOptions(args, authorizationOutput, nowMs),
    );
    const stableVerificationReceipt = {
      schema: PHALA_NONLIVE_BOOTSTRAP_STABLE_VERIFICATION_RECEIPT_SCHEMA,
      status: "canonical_non_live_bootstrap_authorization_stably_verified",
      truth_status:
        "stable_signature_files_verified_not_full_target_descriptor_contract_sigstore_phala_mutation_tdx_late_secret_or_live_authority",
      authorization_receipt: verified.receipt,
      bootstrap_authority_evidence: verified.bootstrap_authority_evidence,
      reviewer_authority_evidence: verified.reviewer_authority_evidence,
      blocker_codes: [
        ...PHALA_NONLIVE_BOOTSTRAP_LOCAL_PUBLICATION_BLOCKER_CODES,
      ],
      production_mutation_ready: false,
      signer_subprocess_invoked: false,
      pinned_signature_verifier_invoked: true,
      network_request_performed: false,
      phala_mutation_performed: false,
      late_secret_activation_authorized: false,
      live_traffic_authorized: false,
    };
    const receiptText = canonicalArtifactText(stableVerificationReceipt);
    receiptSource = writePrivateTemporaryJson(
      path.dirname(receiptOutput),
      "phala-bootstrap-receipt-source",
      receiptText,
    );
    durablyPublishJson({
      sourcePath: receiptSource,
      outputPath: receiptOutput,
      publishMode: "create",
      fileMode: 0o600,
    });
    return {
      schema: PHALA_NONLIVE_BOOTSTRAP_PUBLICATION_RECEIPT_SCHEMA,
      status: "canonical_non_live_authorization_and_receipt_created",
      truth_status:
        "local_create_only_files_with_transitively_allowlisted_signatures_not_phala_mutation_tdx_late_secret_or_live_authority",
      authorization_id: verified.receipt.authorization_id,
      batch_id: verified.receipt.batch_id,
      authorization_artifact_file_sha256:
        verified.receipt.authorization_artifact_file_sha256,
      verification_receipt_sha256: sha256Bytes(Buffer.from(receiptText, "utf8")),
      authorization_output: authorizationOutput,
      receipt_output: receiptOutput,
      blocker_codes: [
        ...PHALA_NONLIVE_BOOTSTRAP_LOCAL_PUBLICATION_BLOCKER_CODES,
      ],
      production_mutation_ready: false,
      signer_subprocess_invoked: false,
      pinned_signature_verifier_invoked: true,
      network_request_performed: false,
      phala_mutation_performed: false,
      late_secret_activation_authorized: false,
      live_traffic_authorized: false,
    };
  } catch (error) {
    if (authorizationPublished) {
      try {
        durablyRemoveJson({
          filePath: authorizationOutput,
          expectedSha256: sha256Bytes(Buffer.from(authorizationText, "utf8")),
          expectedMode: 0o600,
        });
        authorizationPublished = false;
      } catch (rollbackError) {
        throw new Error(
          `receipt publication failed and exact authorization rollback also failed: ${scrubErrorMessage(rollbackError)}`,
          { cause: error },
        );
      }
    }
    throw error;
  } finally {
    safeRemoveTemporary(authorizationSource);
    safeRemoveTemporary(receiptSource);
  }
}

export function runPhalaNonLiveBootstrapAuthorizationCli(argv, {
  stdout = (text) => process.stdout.write(text),
} = {}) {
  const args = parsePhalaNonLiveBootstrapAuthorizationCliArgs(argv);
  if (args.command === "help") {
    stdout(`${PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_CLI_USAGE}\n`);
    return 0;
  }
  if (args.command === "diagnose") {
    const built = createSigningDiagnostic(args);
    stdout(canonicalArtifactText(built.diagnostic));
    return 0;
  }
  const receipt = createNewAuthorization(args);
  stdout(canonicalArtifactText(receipt));
  return 0;
}

async function main() {
  const command = process.argv[2] || "unknown";
  try {
    process.exitCode = runPhalaNonLiveBootstrapAuthorizationCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(operationError(command, error));
    process.exitCode = 1;
  }
}

if (process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await main();
}
