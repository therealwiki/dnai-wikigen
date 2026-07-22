#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertPinnedPhalaPrivateDirectoryPathIdentity,
  closePhalaPinnedPrivateDirectory,
  listPhalaPinnedPrivateEntries,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
  publishPhalaPinnedPrivateFilePendingReady,
} from "./phala-pinned-private-directory.mjs";
import {
  PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
  PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA,
  PHALA_PRODUCTION_POSTLAUNCH_PROJECTION_SCHEMA,
  PHALA_PRODUCTION_POSTLAUNCH_REQUEST_SCHEMA,
  normalizePhalaProductionPostlaunchInputManifest,
  preflightPhalaProductionPostlaunchDependencies,
} from "./phala-production-postlaunch-activation-capability.mjs";
import {
  canonicalResidentAbsolutePath,
  canonicalResidentJsonText,
  exactResidentRecord,
  readStableCanonicalResident0600Json,
  residentRawSha256,
} from "./phala-production-resident-io.mjs";

export const PHALA_PRODUCTION_POSTLAUNCH_ATTACHMENT_RECEIPT_SCHEMA =
  "dnai.phala-production-postlaunch-attachment-receipt.v2";
export const PHALA_PRODUCTION_POSTLAUNCH_ATTACHMENT_FAILED_CODE =
  "phala_production_postlaunch_attachment_failed_closed";

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const MAXIMUM_SOURCE_BYTES = 256 * 1024;
const CLI_FLAGS = Object.freeze([
  "--exchange",
  "--expected-anchor-sha256",
  "--projection",
  "--request",
  "--source",
]);
const PROJECTION_FIELDS = Object.freeze([
  "activation_evidence_lease_expires_at",
  "activation_mutation_authorized",
  "batch_id",
  "chain_id",
  "completed_at",
  "cvm_launch_intent_sha256",
  "deployment_intent_sha256",
  "domains",
  "encrypted_environment_ciphertext_egress",
  "fresh_contract_deployment_receipt_sha256",
  "historical_transcript_file_set_sha256",
  "live_traffic_authorized",
  "private_historical_transcript_contains_raw_quote_bytes",
  "qvl_measurement_policy_set_sha256",
  "raw_private_artifact_egress",
  "raw_quote_external_egress",
  "raw_secret_egress",
  "release_sha",
  "release_verification_authority_sha256",
  "schema",
  "seven_cvm_launch_completion_receipt_sha256",
  "seven_cvm_verified_evidence_set_sha256",
  "status",
  "truth_status",
]);
const REQUEST_FIELDS = Object.freeze([
  "activation_mutation_authorized",
  "automatic_retry_authorized",
  "batch_id",
  "cvm_launch_intent_sha256",
  "deployment_intent_sha256",
  "launch_completion_raw_file_sha256",
  "live_traffic_authorized",
  "manifest_acceptance_deadline",
  "postlaunch_authority_exchange_identity_anchor_sha256",
  "postlaunch_projection_raw_file_sha256",
  "release_sha",
  "release_verification_authority_sha256",
  "required_input",
  "schema",
  "seven_cvm_launch_completion_receipt_sha256",
  "seven_cvm_verified_evidence_set_sha256",
  "status",
  "truth_status",
]);
const SHARED_LINEAGE_FIELDS = Object.freeze([
  "release_sha",
  "batch_id",
  "deployment_intent_sha256",
  "cvm_launch_intent_sha256",
  "release_verification_authority_sha256",
  "seven_cvm_verified_evidence_set_sha256",
  "seven_cvm_launch_completion_receipt_sha256",
]);
const ISO_MILLISECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function usage() {
  return [
    "Usage:",
    "  node scripts/phala-production-postlaunch-attach.mjs \\",
    "    --source /absolute/private/postlaunch-activation-input-manifest.json \\",
    "    --request /absolute/private/postlaunch-authority-request.json \\",
    "    --projection /absolute/private/postlaunch-final-authority-input.json \\",
    "    --exchange /absolute/pinned-postlaunch-authority \\",
    "    --expected-anchor-sha256 sha256:...",
    "",
    "The helper accepts no secrets or signer material. It stable-reads an owned",
    "canonical mode-0600 source outside the exchange, recomputes the raw request",
    "and projection hashes, validates every dependency binding, and durably",
    "creates the one code-owned manifest basename without replacement.",
  ].join("\n");
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function manifestAcceptanceDeadlineMs(value) {
  if (typeof value !== "string" || !ISO_MILLISECOND.test(value)
    || new Date(Date.parse(value)).toISOString() !== value) {
    throw new Error(
      "published postlaunch request manifest deadline is not canonical",
    );
  }
  return Date.parse(value);
}

function validateReleaseAndBatch(value, label) {
  if (!RELEASE_SHA.test(value.release_sha)
    || typeof value.batch_id !== "string" || value.batch_id.length < 8
    || value.batch_id.length > 160 || /[\0\r\n]/.test(value.batch_id)) {
    throw new Error(`${label} release or batch lineage is invalid`);
  }
}

export function parsePhalaProductionPostlaunchAttachmentArgs(argv) {
  if (!Array.isArray(argv)) {
    throw new Error("postlaunch attachment arguments must be one array");
  }
  if (argv.length === 1 && ["--help", "-h"].includes(argv[0])) {
    return Object.freeze({ help: true });
  }
  if (argv.length !== CLI_FLAGS.length * 2) {
    throw new Error("postlaunch attachment requires exactly five path/anchor inputs");
  }
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!CLI_FLAGS.includes(flag) || Object.hasOwn(values, flag)
      || typeof value !== "string" || value.length < 1
      || value.startsWith("--") || String(flag).includes("=")) {
      throw new Error(
        "postlaunch attachment received an unsupported or duplicate argument",
      );
    }
    values[flag] = value;
  }
  if (!SHA256.test(values["--expected-anchor-sha256"])) {
    throw new Error("postlaunch attachment anchor must be a canonical SHA-256");
  }
  const parsed = Object.freeze({
    help: false,
    source: canonicalResidentAbsolutePath(
      values["--source"],
      "postlaunch source manifest",
    ),
    request: canonicalResidentAbsolutePath(
      values["--request"],
      "postlaunch request",
    ),
    projection: canonicalResidentAbsolutePath(
      values["--projection"],
      "postlaunch projection",
    ),
    exchange: canonicalResidentAbsolutePath(
      values["--exchange"],
      "postlaunch authority exchange",
    ),
    expectedAnchorSha256: values["--expected-anchor-sha256"],
  });
  for (const sourcePath of [parsed.source, parsed.request, parsed.projection]) {
    if (sourcePath === parsed.exchange
      || sourcePath.startsWith(`${parsed.exchange}${path.sep}`)) {
      throw new Error("postlaunch attachment sources must remain outside the exchange");
    }
  }
  return parsed;
}

function normalizeProjection(value) {
  const parsed = exactResidentRecord(
    value,
    PROJECTION_FIELDS,
    "published postlaunch projection",
  );
  validateReleaseAndBatch(parsed, "published postlaunch projection");
  if (parsed.schema !== PHALA_PRODUCTION_POSTLAUNCH_PROJECTION_SCHEMA
    || parsed.status
      !== "seven_cvm_launch_completion_persisted_pending_reviewed_final_authority"
    || parsed.truth_status
      !== "public_machine_evidence_projection_not_review_signature_mutation_or_live_authority"
    || parsed.chain_id !== 84_532
    || !Array.isArray(parsed.domains) || parsed.domains.length !== 7
    || parsed.private_historical_transcript_contains_raw_quote_bytes !== true
    || parsed.raw_quote_external_egress !== false
    || parsed.raw_secret_egress !== false
    || parsed.raw_private_artifact_egress !== false
    || parsed.encrypted_environment_ciphertext_egress !== false
    || parsed.activation_mutation_authorized !== false
    || parsed.live_traffic_authorized !== false) {
    throw new Error("published postlaunch projection posture is invalid");
  }
  for (const field of [
    "deployment_intent_sha256",
    "cvm_launch_intent_sha256",
    "fresh_contract_deployment_receipt_sha256",
    "release_verification_authority_sha256",
    "seven_cvm_verified_evidence_set_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
    "historical_transcript_file_set_sha256",
    "qvl_measurement_policy_set_sha256",
  ]) exactSha256(parsed[field], `published projection ${field}`);
  return Object.freeze({ ...parsed });
}

function normalizeRequest(value, expectedAnchorSha256) {
  const parsed = exactResidentRecord(
    value,
    REQUEST_FIELDS,
    "published postlaunch request",
  );
  validateReleaseAndBatch(parsed, "published postlaunch request");
  const required = exactResidentRecord(
    parsed.required_input,
    ["basename", "canonical_json_required", "mode", "schema"],
    "published postlaunch required input",
  );
  if (parsed.schema !== PHALA_PRODUCTION_POSTLAUNCH_REQUEST_SCHEMA
    || parsed.status !== "waiting_for_exact_postlaunch_activation_input_manifest"
    || parsed.truth_status
      !== "transport_request_only_not_review_signature_mutation_or_live_authority"
    || required.basename !== PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME
    || required.mode !== "0600" || required.canonical_json_required !== true
    || required.schema !== PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA
    || parsed.postlaunch_authority_exchange_identity_anchor_sha256
      !== expectedAnchorSha256
    || parsed.automatic_retry_authorized !== false
    || parsed.activation_mutation_authorized !== false
    || parsed.live_traffic_authorized !== false) {
    throw new Error("published postlaunch request posture is invalid");
  }
  for (const field of [
    "deployment_intent_sha256",
    "cvm_launch_intent_sha256",
    "launch_completion_raw_file_sha256",
    "postlaunch_projection_raw_file_sha256",
    "release_verification_authority_sha256",
    "seven_cvm_verified_evidence_set_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
  ]) exactSha256(parsed[field], `published request ${field}`);
  manifestAcceptanceDeadlineMs(parsed.manifest_acceptance_deadline);
  return Object.freeze({ ...parsed, required_input: Object.freeze({ ...required }) });
}

function expectedManifestLineage({ request, requestRawSha256 }) {
  return Object.freeze({
    release_sha: request.release_sha,
    batch_id: request.batch_id,
    deployment_intent_sha256: request.deployment_intent_sha256,
    cvm_launch_intent_sha256: request.cvm_launch_intent_sha256,
    manifest_acceptance_deadline: request.manifest_acceptance_deadline,
    release_verification_authority_sha256:
      request.release_verification_authority_sha256,
    seven_cvm_verified_evidence_set_sha256:
      request.seven_cvm_verified_evidence_set_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      request.seven_cvm_launch_completion_receipt_sha256,
    postlaunch_projection_raw_file_sha256:
      request.postlaunch_projection_raw_file_sha256,
    postlaunch_request_raw_file_sha256: requestRawSha256,
  });
}

export function attachPhalaProductionPostlaunchManifest(input = {}) {
  const parsed = exactResidentRecord(
    input,
    ["exchange", "expectedAnchorSha256", "projection", "request", "source"],
    "postlaunch attachment input",
  );
  const {
    source,
    request,
    projection,
    exchange,
    expectedAnchorSha256,
  } = parsed;
  for (const sourcePath of [source, request, projection, exchange]) {
    canonicalResidentAbsolutePath(sourcePath, "postlaunch attachment path");
  }
  if (!SHA256.test(expectedAnchorSha256)) {
    throw new Error("postlaunch attachment anchor must be a canonical SHA-256");
  }
  for (const sourcePath of [source, request, projection]) {
    if (sourcePath === exchange || sourcePath.startsWith(`${exchange}${path.sep}`)) {
      throw new Error("postlaunch attachment sources must remain outside the exchange");
    }
  }
  const sourceRead = readStableCanonicalResident0600Json(
    source,
    "postlaunch source manifest",
    { maximum: MAXIMUM_SOURCE_BYTES },
  );
  const requestRead = readStableCanonicalResident0600Json(
    request,
    "published postlaunch request",
    { maximum: 128 * 1024 },
  );
  const projectionRead = readStableCanonicalResident0600Json(
    projection,
    "published postlaunch projection",
    { maximum: 512 * 1024 },
  );
  const normalizedRequest = normalizeRequest(
    requestRead.value,
    expectedAnchorSha256,
  );
  const acceptanceDeadlineMs = manifestAcceptanceDeadlineMs(
    normalizedRequest.manifest_acceptance_deadline,
  );
  if (Date.now() >= acceptanceDeadlineMs) {
    throw new Error("postlaunch attachment manifest acceptance deadline expired");
  }
  const normalizedProjection = normalizeProjection(projectionRead.value);
  const requestRawSha256 = residentRawSha256(requestRead.bytes);
  const projectionRawSha256 = residentRawSha256(projectionRead.bytes);
  if (normalizedRequest.postlaunch_projection_raw_file_sha256
      !== projectionRawSha256
    || SHARED_LINEAGE_FIELDS.some(
      (field) => normalizedRequest[field] !== normalizedProjection[field],
    )) {
    throw new Error("published postlaunch request and projection lineage differ");
  }
  const normalizedManifest = normalizePhalaProductionPostlaunchInputManifest(
    sourceRead.value,
    expectedManifestLineage({
      request: normalizedRequest,
      requestRawSha256,
    }),
  );
  // The helper reads every referenced inode without following links before it
  // can create the authority entry. Paths and file contents remain private.
  preflightPhalaProductionPostlaunchDependencies(
    normalizedManifest.dependencies,
  );
  if (Date.now() >= acceptanceDeadlineMs) {
    throw new Error("postlaunch attachment manifest acceptance deadline expired");
  }
  const handle = pinPhalaPrivateDirectory(exchange, {
    expectedIdentityAnchorSha256: expectedAnchorSha256,
  });
  try {
    assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
    if (phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle)
        !== expectedAnchorSha256) {
      throw new Error("postlaunch pinned exchange anchor changed");
    }
    if (listPhalaPinnedPrivateEntries(handle).length !== 0) {
      throw new Error("postlaunch authority exchange must be exactly empty before attach");
    }
    if (Date.now() >= acceptanceDeadlineMs) {
      throw new Error("postlaunch attachment manifest acceptance deadline expired");
    }
    const identity = publishPhalaPinnedPrivateFilePendingReady(
      handle,
      PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
      sourceRead.bytes,
      {
        maximum: MAXIMUM_SOURCE_BYTES,
        readyDeadlineMs: acceptanceDeadlineMs,
      },
    );
    assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
    if (JSON.stringify(listPhalaPinnedPrivateEntries(handle))
        !== JSON.stringify([
          PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
        ])) {
      throw new Error(
        "postlaunch authority exchange namespace changed during attach",
      );
    }
    return Object.freeze({
      schema: PHALA_PRODUCTION_POSTLAUNCH_ATTACHMENT_RECEIPT_SCHEMA,
      status:
        "postlaunch_manifest_atomically_attached_pending_same_process_coordinator_validation",
      truth_status:
        "non_signing_non_secret_transport_only_not_mutation_or_live_authority",
      release_sha: normalizedRequest.release_sha,
      batch_id: normalizedRequest.batch_id,
      postlaunch_request_raw_file_sha256: requestRawSha256,
      postlaunch_projection_raw_file_sha256: projectionRawSha256,
      postlaunch_manifest_raw_file_sha256: identity.sha256,
      manifest_acceptance_deadline:
        normalizedRequest.manifest_acceptance_deadline,
      postlaunch_authority_exchange_identity_anchor_sha256:
        expectedAnchorSha256,
      manifest_basename: PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
      manifest_mode: identity.mode,
      source_bytes_copied_exactly: identity.size === sourceRead.bytes.length,
      signer_key_material_accepted: false,
      raw_secret_input_accepted: false,
      automatic_retry_authorized: false,
      activation_mutation_authorized: false,
      live_traffic_authorized: false,
    });
  } finally {
    closePhalaPinnedPrivateDirectory(handle);
  }
}

export function main(argv = process.argv.slice(2)) {
  const parsed = parsePhalaProductionPostlaunchAttachmentArgs(argv);
  if (parsed.help) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  const receipt = attachPhalaProductionPostlaunchManifest({
    source: parsed.source,
    request: parsed.request,
    projection: parsed.projection,
    exchange: parsed.exchange,
    expectedAnchorSha256: parsed.expectedAnchorSha256,
  });
  process.stdout.write(canonicalResidentJsonText(receipt));
  return 0;
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    process.exitCode = main();
  } catch {
    process.stderr.write(
      `${PHALA_PRODUCTION_POSTLAUNCH_ATTACHMENT_FAILED_CODE}\n`,
    );
    process.exitCode = 1;
  }
}
