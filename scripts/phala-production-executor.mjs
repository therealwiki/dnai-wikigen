#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  PHALA_PRODUCTION_BOOTSTRAP_IMPLEMENTED_CONTROL_CODES,
  PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_LIVE_ACTIVATION_BLOCKER_CODES,
  PHALA_PRODUCTION_POST_MEASUREMENT_BLOCKER_CODES,
} from "./phala-production-execution-policy.mjs";
import {
  PHALA_EXACT_SDK_CALL_SEQUENCE,
  PHALA_EXECUTION_ORDER,
} from "./phala-production-executor-core.mjs";
import { createPhalaCompatibilityProbePlan } from "./phala-production-target-authority.mjs";

export const PHALA_PRODUCTION_BOOTSTRAP_STATUS_SCHEMA =
  "dnai.phala-production-bootstrap-status.v2";
export const PHALA_PRODUCTION_EXECUTION_FAILED_CODE =
  "phala_production_execution_failed_closed";

function usage() {
  return [
    "Usage:",
    "  node scripts/phala-production-executor.mjs --status-json",
    "  node scripts/phala-production-executor.mjs --compatibility-plan-json",
    "  node scripts/phala-production-executor.mjs --execute-request /absolute/private-request.json",
    "",
    "Status and compatibility-plan commands are read-only. Execution uses only the",
    "canonical 0600 request file, current canonical Phala profile, signed authorities,",
    "durable recovery journal, and exact production runtime; no CLI mutation bypass exists.",
  ].join("\n");
}

export function phalaProductionBootstrapStatus() {
  return {
    schema: PHALA_PRODUCTION_BOOTSTRAP_STATUS_SCHEMA,
    availability: true,
    reason_code: null,
    blocker_codes: [...PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES],
    bootstrap_blocker_codes: [
      ...PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
    ],
    implemented_control_codes: [
      ...PHALA_PRODUCTION_BOOTSTRAP_IMPLEMENTED_CONTROL_CODES,
    ],
    post_measurement_blocker_codes: [
      ...PHALA_PRODUCTION_POST_MEASUREMENT_BLOCKER_CODES,
    ],
    live_activation_blocker_codes: [
      ...PHALA_PRODUCTION_LIVE_ACTIVATION_BLOCKER_CODES,
    ],
    execution_order: [...PHALA_EXECUTION_ORDER],
    exact_sdk_call_sequence: [...PHALA_EXACT_SDK_CALL_SEQUENCE],
    execution_module: "scripts/phala-production-executor-runtime.mjs",
    phala_sdk_imported: false,
    credential_file_read: false,
    process_environment_credential_read: false,
    network_call_performed: false,
    phala_mutation_performed: false,
    caller_supplied_client_accepted: false,
    caller_supplied_callback_accepted: false,
    automatic_retry_authorized: false,
    redirects_authorized: false,
  };
}

function readPrivateExecutionRequest(filePath) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)) {
    throw new Error("production execution request path must be absolute");
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.uid !== process.getuid()
      || (before.mode & 0o777) !== 0o600
      || before.size < 2 || before.size > 128 * 1024) {
      throw new Error("production execution request must be an owned bounded 0600 regular file");
    }
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    if (before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs
      || bytes.length !== before.size) {
      throw new Error("production execution request changed during stable read");
    }
    const text = bytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(bytes) || !text.endsWith("\n")) {
      throw new Error("production execution request is not canonical UTF-8 JSON text");
    }
    const value = JSON.parse(text);
    if (`${JSON.stringify(value, null, 2)}\n` !== text) {
      throw new Error("production execution request JSON bytes are not canonical");
    }
    return value;
  } finally {
    fs.closeSync(fd);
  }
}

export async function main(argv = process.argv.slice(2)) {
  if (!Array.isArray(argv) || argv.length < 1 || argv.length > 2) {
    throw new Error("production bootstrap accepts one exact operation and optional request path");
  }
  if (argv[0] === "--help" && argv.length === 1) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  if (argv[0] === "--status-json" && argv.length === 1) {
    process.stdout.write(`${JSON.stringify(phalaProductionBootstrapStatus(), null, 2)}\n`);
    return 0;
  }
  if (argv[0] === "--compatibility-plan-json" && argv.length === 1) {
    process.stdout.write(`${JSON.stringify(createPhalaCompatibilityProbePlan(), null, 2)}\n`);
    return 0;
  }
  if (argv[0] === "--execute-request" && argv.length === 2) {
    const request = readPrivateExecutionRequest(argv[1]);
    const runtime = await import("./phala-production-executor-runtime.mjs");
    const result = await runtime.executePhalaSevenCvmProductionLaunch(request);
    process.stdout.write(`${JSON.stringify({
      schema: result.schema,
      status: result.status,
      release_sha: result.release_sha,
      batch_id: result.batch_id,
      executor_final_state_sha256: result.executor_final_state_sha256,
      execution_replay_sha256: result.execution_replay_sha256,
      live_traffic_authorized: false,
    }, null, 2)}\n`);
    return 0;
  }
  throw new Error("unknown production executor operation");
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().then(
    (code) => { process.exitCode = code; },
    () => {
      process.stderr.write(`${PHALA_PRODUCTION_EXECUTION_FAILED_CODE}\n`);
      process.exitCode = 1;
    },
  );
}
