#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalLowSEip191Signature,
  executionPolicyReviewerHash,
  verifyIndependentEip191PersonalSignature,
} from "./release-authority-signature-verifier-core.mjs";
import {
  MAX_RELEASE_AUTHORITY_REVIEW_LIFETIME_MS,
  MIN_RELEASE_AUTHORITY_REVIEW_HEADROOM_MS,
  RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
  RELEASE_AUTHORITY_SIGNATURE_SCHEME,
  ceremonyAuthorizationReviewSigningPayload,
  releaseAuthorityReviewSigningMessage,
  releaseAuthorityReviewSigningPayloadSha256,
  reviewSigningPayload,
} from "./release-ceremony-authorization.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
} from "./phala-pinned-private-directory.mjs";
import {
  canonicalResidentAbsolutePath,
  canonicalResidentJsonText,
  exactResidentRecord,
  parsePinnedCanonicalResident0600Json,
  residentRawSha256,
} from "./phala-production-resident-io.mjs";

export const PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_SCHEMA =
  "dnai.phala-production-stage-b-attachment-manifest.v2";
export const PHALA_PRODUCTION_STAGE_B_EXTERNAL_SIGNATURES_SCHEMA =
  "dnai.phala-production-stage-b-external-signatures.v1";
export const PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_BASENAME =
  "stage-b-attachment-manifest.json";
export const PHALA_PRODUCTION_STAGE_B_ATTACHMENT_FAILED_CODE =
  "phala_production_stage_b_attachment_failed_closed";

const MAXIMUM_SIGNING_BYTES = 4 * 1024 * 1024;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const MAXIMUM_FUTURE_SKEW_MS = 5 * 60 * 1_000;
const LEGACY_STAGE_B_ATTACHMENT_MANIFEST_SCHEMA =
  "dnai.phala-production-stage-b-attachment-manifest.v1";

function usage() {
  return [
    "Usage:",
    "  node scripts/phala-production-stage-b-attach.mjs \\",
    "    --exchange /absolute/new-stage-b-exchange \\",
    "    --expected-anchor-sha256 sha256:...",
    "",
    "The helper reads the driver-issued 0600 attachment manifest and the exact",
    "external-signatures input in that pinned 0700 exchange, verifies but never",
    "creates signatures, and creates the coordinator-owned signed-B output once.",
    "Private keys, mnemonics, keystores, signer commands, accounts, RPCs, and",
    "credential inputs are not accepted.",
  ].join("\n");
}

export function parsePhalaProductionStageBAttachmentArgs(argv) {
  if (!Array.isArray(argv)) throw new Error("Stage-B arguments must be one array");
  if (argv.length === 1 && ["--help", "-h"].includes(argv[0])) {
    return Object.freeze({ help: true });
  }
  const fields = Object.freeze(["--exchange", "--expected-anchor-sha256"]);
  if (argv.length !== fields.length * 2) {
    throw new Error("Stage-B attachment requires exactly exchange and anchor inputs");
  }
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!fields.includes(flag) || Object.hasOwn(values, flag)
      || typeof value !== "string" || value.length < 1
      || value.startsWith("--") || String(flag).includes("=")) {
      throw new Error("Stage-B attachment received an unsupported or duplicate argument");
    }
    values[flag] = value;
  }
  if (Object.keys(values).length !== fields.length) {
    throw new Error("Stage-B attachment inputs are incomplete");
  }
  if (!SHA256.test(values["--expected-anchor-sha256"])) {
    throw new Error("Stage-B attachment anchor must be a canonical SHA-256");
  }
  return Object.freeze({
    help: false,
    exchange: canonicalResidentAbsolutePath(
      values["--exchange"],
      "Stage-B exchange",
    ),
    expectedAnchorSha256: values["--expected-anchor-sha256"],
  });
}

function normalizePublicFile(value, label) {
  const parsed = exactResidentRecord(
    value,
    ["basename", "mode", "sha256", "size"],
    label,
  );
  if (typeof parsed.basename !== "string"
    || path.basename(parsed.basename) !== parsed.basename
    || !/^[A-Za-z0-9._-]{1,255}$/.test(parsed.basename)
    || parsed.mode !== "0600" || !SHA256.test(parsed.sha256)
    || !Number.isSafeInteger(parsed.size) || parsed.size < 2
    || parsed.size > MAXIMUM_SIGNING_BYTES) {
    throw new Error(`${label} identity is invalid`);
  }
  return Object.freeze({ ...parsed });
}

function normalizeCodeOwnedFile(value, label) {
  const parsed = exactResidentRecord(
    value,
    ["basename", "canonical_json_required", "mode"],
    label,
  );
  if (typeof parsed.basename !== "string"
    || path.basename(parsed.basename) !== parsed.basename
    || !/^[A-Za-z0-9._-]{1,255}$/.test(parsed.basename)
    || parsed.mode !== "0600" || parsed.canonical_json_required !== true) {
    throw new Error(`${label} is invalid`);
  }
  return Object.freeze({ ...parsed });
}

export function normalizePhalaProductionStageBAttachmentManifest(
  value,
  expectedAnchorSha256,
) {
  if (value && typeof value === "object" && !Array.isArray(value)
    && value.schema === LEGACY_STAGE_B_ATTACHMENT_MANIFEST_SCHEMA) {
    throw new Error(
      "legacy Stage-B attachment manifest v1 is not accepted by the live v2 transport",
    );
  }
  const parsed = exactResidentRecord(value, [
    "activation_mutation_authorized",
    "automatic_retry_authorized",
    "batch_id",
    "external_signatures_input",
    "live_traffic_authorized",
    "release_sha",
    "schema",
    "signed_b_output",
    "signing_exchange_directory_identity_anchor_sha256",
    "signing_message",
    "signing_payload_file",
    "signing_payload_sha256",
    "stage_b_review_reviewer_authority_current_status_epoch",
    "stage_b_review_reviewer_authority_current_status_sha256",
    "stage_b_reviewer_status_history_raw_file_sha256",
    "status",
    "truth_status",
    "unsigned_body_file",
  ], "Stage-B attachment manifest");
  const unsignedBodyFile = normalizePublicFile(
    parsed.unsigned_body_file,
    "Stage-B unsigned body file",
  );
  const signingPayloadFile = normalizePublicFile(
    parsed.signing_payload_file,
    "Stage-B signing payload file",
  );
  const externalSignaturesInput = normalizeCodeOwnedFile(
    parsed.external_signatures_input,
    "Stage-B external signatures input",
  );
  const signedBOutput = normalizeCodeOwnedFile(
    parsed.signed_b_output,
    "Stage-B signed output",
  );
  if (parsed.schema !== PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_SCHEMA
    || parsed.status !== "waiting_for_external_two_reviewer_signatures"
    || parsed.truth_status
      !== "non_signing_candidate_attachment_only_same_process_coordinator_validation_still_required"
    || !RELEASE_SHA.test(parsed.release_sha)
    || typeof parsed.batch_id !== "string" || parsed.batch_id.length < 8
    || parsed.batch_id.length > 160
    || !SHA256.test(parsed.signing_payload_sha256)
    || parsed.signing_exchange_directory_identity_anchor_sha256
      !== expectedAnchorSha256
    || !SHA256.test(
      parsed.stage_b_reviewer_status_history_raw_file_sha256,
    )
    || !Number.isSafeInteger(
      parsed.stage_b_review_reviewer_authority_current_status_epoch,
    )
    || parsed.stage_b_review_reviewer_authority_current_status_epoch < 1
    || !SHA256.test(
      parsed.stage_b_review_reviewer_authority_current_status_sha256,
    )
    || typeof parsed.signing_message !== "string"
    || parsed.signing_message.length < 32 || parsed.signing_message.length > 512
    || parsed.automatic_retry_authorized !== false
    || parsed.activation_mutation_authorized !== false
    || parsed.live_traffic_authorized !== false) {
    throw new Error("Stage-B attachment manifest authority boundary is invalid");
  }
  if (!unsignedBodyFile.basename.endsWith(".unsigned-body.json")) {
    throw new Error("Stage-B unsigned body basename is invalid");
  }
  const prefix = unsignedBodyFile.basename.slice(
    0,
    -".unsigned-body.json".length,
  );
  if (prefix.length < 16
    || signingPayloadFile.basename !== `${prefix}.signing-payload.json`
    || externalSignaturesInput.basename !== `${prefix}.external-signatures.json`
    || signedBOutput.basename !== `${prefix}.signed.json`) {
    throw new Error("Stage-B exchange basenames do not share one code-owned prefix");
  }
  return Object.freeze({
    ...parsed,
    unsigned_body_file: unsignedBodyFile,
    signing_payload_file: signingPayloadFile,
    external_signatures_input: externalSignaturesInput,
    signed_b_output: signedBOutput,
  });
}

function readPinnedBoundJson(handle, identity, label) {
  const read = parsePinnedCanonicalResident0600Json(
    handle,
    identity.basename,
    label,
    { maximum: MAXIMUM_SIGNING_BYTES },
  );
  if (read.bytes.length !== identity.size
    || residentRawSha256(read.bytes) !== identity.sha256) {
    throw new Error(`${label} differs from the driver-authenticated identity`);
  }
  return read;
}

function stageBReviewMetadata(payload) {
  return Object.freeze({
    reviewer_authority_genesis_sha256:
      payload.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      payload.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      payload.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      payload.reviewer_authority_current_status_sha256,
    approved_reviewer_hashes: payload.approved_reviewer_hashes,
    reviewer_root_hash: payload.reviewer_root_hash,
    reviewer_set_sha256: payload.reviewer_set_sha256,
    signed_at: payload.signed_at,
    expires_at: payload.expires_at,
  });
}

function normalizeExternalSignatures(value, payload) {
  const parsed = exactResidentRecord(value, [
    "purpose",
    "schema",
    "signature_scheme",
    "signatures",
    "signing_payload_sha256",
  ], "Stage-B external signature envelope");
  const payloadSha256 = releaseAuthorityReviewSigningPayloadSha256(payload);
  if (parsed.schema !== PHALA_PRODUCTION_STAGE_B_EXTERNAL_SIGNATURES_SCHEMA
    || parsed.purpose !== "stage_b_ceremony_authorization_review"
    || parsed.signature_scheme !== RELEASE_AUTHORITY_SIGNATURE_SCHEME
    || parsed.signing_payload_sha256 !== payloadSha256
    || !Array.isArray(parsed.signatures) || parsed.signatures.length !== 2) {
    throw new Error("Stage-B external signatures do not bind the exact payload");
  }
  const signingMessage = releaseAuthorityReviewSigningMessage(payload);
  const signatures = parsed.signatures.map((entry, index) => {
    const signature = exactResidentRecord(
      entry,
      ["address", "controller_id", "signature"],
      `Stage-B external signature ${index}`,
    );
    if (!ADDRESS.test(signature.address)
      || !CONTROLLER.test(signature.controller_id)
      || !payload.approved_reviewer_hashes.includes(
        executionPolicyReviewerHash(signature.address),
      )) {
      throw new Error("Stage-B signer is outside the payload-approved reviewer root");
    }
    const canonicalSignature = canonicalLowSEip191Signature(
      signature.signature,
      `Stage-B external signature ${index}`,
    );
    verifyIndependentEip191PersonalSignature({
      address: signature.address,
      message: signingMessage,
      signature: canonicalSignature,
    });
    return Object.freeze({
      address: signature.address,
      controller_id: signature.controller_id,
      signature: canonicalSignature,
    });
  });
  if (signatures[0].address >= signatures[1].address
    || signatures[0].controller_id === signatures[1].controller_id) {
    throw new Error("Stage-B signatures must use sorted distinct signers and controllers");
  }
  return Object.freeze(signatures);
}

export function attachPhalaProductionStageB({
  exchange,
  expectedAnchorSha256,
} = {}) {
  const handle = pinPhalaPrivateDirectory(exchange, {
    expectedIdentityAnchorSha256: expectedAnchorSha256,
  });
  try {
    if (phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle)
        !== expectedAnchorSha256) {
      throw new Error("Stage-B pinned exchange anchor changed");
    }
    const manifestRead = parsePinnedCanonicalResident0600Json(
      handle,
      PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_BASENAME,
      "Stage-B attachment manifest",
      { maximum: 64 * 1024 },
    );
    const manifest = normalizePhalaProductionStageBAttachmentManifest(
      manifestRead.value,
      expectedAnchorSha256,
    );
    const bodyRead = readPinnedBoundJson(
      handle,
      manifest.unsigned_body_file,
      "Stage-B unsigned body",
    );
    const payloadRead = readPinnedBoundJson(
      handle,
      manifest.signing_payload_file,
      "Stage-B signing payload",
    );
    if (Object.hasOwn(bodyRead.value, "review")) {
      throw new Error("Stage-B unsigned body must not already contain a review");
    }
    const payload = reviewSigningPayload(payloadRead.value);
    if (manifest.stage_b_review_reviewer_authority_current_status_epoch
        !== payload.reviewer_authority_current_status_epoch
      || manifest.stage_b_review_reviewer_authority_current_status_sha256
        !== payload.reviewer_authority_current_status_sha256) {
      throw new Error(
        "Stage-B attachment manifest reviewer-status head differs from the exact signed review payload",
      );
    }
    const recomputedPayload = ceremonyAuthorizationReviewSigningPayload(
      bodyRead.value,
      stageBReviewMetadata(payload),
    );
    const payloadSha256 = releaseAuthorityReviewSigningPayloadSha256(payload);
    if (canonicalResidentJsonText(recomputedPayload) !== payloadRead.text
      || payloadSha256 !== manifest.signing_payload_sha256
      || releaseAuthorityReviewSigningMessage(payload)
        !== manifest.signing_message) {
      throw new Error("Stage-B payload is not the exact projection of its unsigned body");
    }
    const signedAt = Date.parse(payload.signed_at);
    const expiresAt = Date.parse(payload.expires_at);
    const checkedAt = Date.now();
    if (!Number.isFinite(signedAt) || !Number.isFinite(expiresAt)
      || expiresAt <= signedAt
      || expiresAt - signedAt > MAX_RELEASE_AUTHORITY_REVIEW_LIFETIME_MS
      || signedAt > checkedAt + MAXIMUM_FUTURE_SKEW_MS
      || expiresAt - checkedAt < MIN_RELEASE_AUTHORITY_REVIEW_HEADROOM_MS) {
      throw new Error("Stage-B signing lease is stale or lacks activation headroom");
    }
    const signatureRead = parsePinnedCanonicalResident0600Json(
      handle,
      manifest.external_signatures_input.basename,
      "Stage-B external signatures",
      { maximum: 64 * 1024 },
    );
    const signatures = normalizeExternalSignatures(signatureRead.value, payload);
    const review = Object.freeze({
      ...payload,
      schema: RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
      signing_payload_sha256: payloadSha256,
      signatures,
    });
    const signedBBytes = Buffer.from(canonicalResidentJsonText({
      ...bodyRead.value,
      review,
    }), "utf8");
    const identity = createExclusivePhalaPinnedPrivateFile(
      handle,
      manifest.signed_b_output.basename,
      signedBBytes,
      { mode: 0o600, maximum: MAXIMUM_SIGNING_BYTES },
    );
    return Object.freeze({
      schema: "dnai.phala-production-stage-b-attachment-receipt.v2",
      status: "candidate_signed_b_attached_pending_same_process_coordinator_validation",
      truth_status:
        "two_external_signatures_independently_replayed_no_signing_key_or_activation_capability_accepted",
      release_sha: manifest.release_sha,
      batch_id: manifest.batch_id,
      signing_payload_sha256: payloadSha256,
      stage_b_reviewer_status_history_raw_file_sha256:
        manifest.stage_b_reviewer_status_history_raw_file_sha256,
      stage_b_review_reviewer_authority_current_status_epoch:
        payload.reviewer_authority_current_status_epoch,
      stage_b_review_reviewer_authority_current_status_sha256:
        payload.reviewer_authority_current_status_sha256,
      signed_b_output_basename: manifest.signed_b_output.basename,
      signed_b_output_sha256: identity.sha256,
      signature_count: 2,
      signer_key_material_accepted: false,
      activation_mutation_authorized: false,
      live_traffic_authorized: false,
    });
  } finally {
    closePhalaPinnedPrivateDirectory(handle);
  }
}

export function main(argv = process.argv.slice(2)) {
  const parsed = parsePhalaProductionStageBAttachmentArgs(argv);
  if (parsed.help) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  const receipt = attachPhalaProductionStageB(parsed);
  process.stdout.write(`${canonicalResidentJsonText(receipt)}`);
  return 0;
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    process.exitCode = main();
  } catch {
    process.stderr.write(`${PHALA_PRODUCTION_STAGE_B_ATTACHMENT_FAILED_CODE}\n`);
    process.exitCode = 1;
  }
}
