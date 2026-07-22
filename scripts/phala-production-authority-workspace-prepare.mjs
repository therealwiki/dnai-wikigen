#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertPinnedPhalaPrivateDirectoryPathIdentity,
  closePhalaPinnedPrivateDirectory,
  listPhalaPinnedPrivateEntries,
  phalaPinnedPrivateDirectoryIdentityAnchorPath,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
} from "./phala-pinned-private-directory.mjs";
import {
  canonicalResidentAbsolutePath,
  canonicalResidentJsonText,
  exactResidentRecord,
  readStableCanonicalResident0600Json,
  residentRawSha256,
} from "./phala-production-resident-io.mjs";

export const PHALA_PRODUCTION_AUTHORITY_WORKSPACE_PREPARE_REQUEST_SCHEMA =
  "dnai.phala-production-authority-workspace-prepare-request.v2";
export const PHALA_PRODUCTION_AUTHORITY_WORKSPACE_PREPARATION_RECEIPT_SCHEMA =
  "dnai.phala-production-authority-workspace-preparation-receipt.v2";

const AUTHORITY_FIELDS = Object.freeze([
  "evidenceExchangePath",
  "outputPath",
  "postlaunchAuthorityExchangePath",
  "signingExchangePath",
]);

function usage() {
  return [
    "Usage:",
    "  node scripts/phala-production-authority-workspace-prepare.mjs \\",
    "    --prepare-request /absolute/private-workspace-request.json",
    "",
    "This is non-authorizing filesystem setup. It initializes or strictly",
    "reopens four empty 0700 directories, prints their observed identity-anchor",
    "digests, and does not authorize CVM mutation, activation, or live traffic.",
    "The printed receipt must be independently reviewed before its exact",
    "path+anchor pairs are sealed into the resident activation request.",
  ].join("\n");
}

function assertDisjoint(paths) {
  if (new Set(paths).size !== paths.length) {
    throw new Error("workspace authority paths must be pairwise distinct");
  }
  for (let left = 0; left < paths.length; left += 1) {
    for (let right = left + 1; right < paths.length; right += 1) {
      if (paths[left].startsWith(`${paths[right]}${path.sep}`)
        || paths[right].startsWith(`${paths[left]}${path.sep}`)) {
        throw new Error("workspace authority paths must not contain one another");
      }
    }
  }
}

function locallyObservedExistingAnchorSha256(directory) {
  const anchorPath = phalaPinnedPrivateDirectoryIdentityAnchorPath(directory);
  if (!fs.existsSync(anchorPath)) return null;
  const read = readStableCanonicalResident0600Json(
    anchorPath,
    "existing workspace identity anchor",
    { maximum: 4096 },
  );
  return residentRawSha256(read.bytes);
}

function prepareOne(directory, label) {
  const observedAnchor = locallyObservedExistingAnchorSha256(directory);
  const handle = pinPhalaPrivateDirectory(directory, observedAnchor === null
    ? {}
    : { expectedIdentityAnchorSha256: observedAnchor });
  try {
    assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
    if (listPhalaPinnedPrivateEntries(handle).length !== 0) {
      throw new Error(`${label} must be empty at filesystem preparation`);
    }
    return Object.freeze({
      handle,
      label,
      authority: Object.freeze({
      path: directory,
      identity_anchor_sha256:
        phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle),
      }),
    });
  } catch (error) {
    closePhalaPinnedPrivateDirectory(handle);
    throw error;
  }
}

export function preparePhalaProductionAuthorityWorkspace(value) {
  const parsed = exactResidentRecord(
    value,
    ["authorities", "schema"],
    "authority-workspace preparation request",
  );
  if (parsed.schema !== PHALA_PRODUCTION_AUTHORITY_WORKSPACE_PREPARE_REQUEST_SCHEMA) {
    throw new Error("authority-workspace preparation request schema is invalid");
  }
  const authorities = exactResidentRecord(
    parsed.authorities,
    AUTHORITY_FIELDS,
    "authority-workspace paths",
  );
  const paths = Object.fromEntries(AUTHORITY_FIELDS.map((field) => [
    field,
    canonicalResidentAbsolutePath(
      authorities[field],
      `authority-workspace ${field}`,
    ),
  ]));
  assertDisjoint(Object.values(paths));

  const opened = [];
  try {
    opened.push(prepareOne(
      paths.evidenceExchangePath,
      "evidence exchange authority",
    ));
    opened.push(prepareOne(
      paths.postlaunchAuthorityExchangePath,
      "postlaunch final-authority exchange authority",
    ));
    opened.push(prepareOne(
      paths.signingExchangePath,
      "Stage-B signing exchange authority",
    ));
    opened.push(prepareOne(
      paths.outputPath,
      "bounded output authority",
    ));
    for (const entry of opened) {
      assertPinnedPhalaPrivateDirectoryPathIdentity(entry.handle);
      if (listPhalaPinnedPrivateEntries(entry.handle).length !== 0
        || phalaPinnedPrivateDirectoryIdentityAnchorSha256(entry.handle)
          !== entry.authority.identity_anchor_sha256) {
        throw new Error(`${entry.label} changed before preparation receipt projection`);
      }
    }
    return Object.freeze({
      schema: PHALA_PRODUCTION_AUTHORITY_WORKSPACE_PREPARATION_RECEIPT_SCHEMA,
      status: "filesystem_authorities_initialized_pending_external_review_and_request_sealing",
      truth_status:
        "local_empty_directory_and_identity_anchor_observation_only_not_activation_authority",
      resident_activation_authorities: Object.freeze({
        evidenceExchangeAuthority: opened[0].authority,
        outputAuthority: opened[3].authority,
        postlaunchAuthorityExchangeAuthority: opened[1].authority,
        signingExchangeAuthority: opened[2].authority,
      }),
      directories_empty_at_observation: true,
      externally_reviewed_and_sealed_into_activation_request: false,
      capability_minted: false,
      activation_mutation_authorized: false,
      automatic_retry_authorized: false,
      live_traffic_authorized: false,
    });
  } finally {
    for (const entry of opened) {
      closePhalaPinnedPrivateDirectory(entry.handle);
    }
  }
}

export async function main(argv = process.argv.slice(2)) {
  if (argv.length === 1 && ["--help", "-h"].includes(argv[0])) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  if (argv.length !== 2 || argv[0] !== "--prepare-request") {
    throw new Error("workspace preparation accepts one exact 0600 request path");
  }
  const requestPath = canonicalResidentAbsolutePath(
    argv[1],
    "authority-workspace preparation request",
  );
  const read = readStableCanonicalResident0600Json(
    requestPath,
    "authority-workspace preparation request",
    { maximum: 32 * 1024 },
  );
  const receipt = preparePhalaProductionAuthorityWorkspace(read.value);
  process.stdout.write(canonicalResidentJsonText(receipt));
  return 0;
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().then(
    (code) => { process.exitCode = code; },
    () => {
      process.stderr.write("authority_workspace_preparation_failed\n");
      process.exitCode = 1;
    },
  );
}
