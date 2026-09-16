import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PHALA_PRODUCTION_BOOTSTRAP_IMPLEMENTED_CONTROL_CODES,
  PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
  PHALA_LIVE_ACTIVATION_AUTHORITY_MISSING,
  PHALA_PRODUCTION_LIVE_ACTIVATION_BLOCKER_CODES,
  PHALA_PRODUCTION_POST_MEASUREMENT_BLOCKER_CODES,
} from "./phala-production-execution-policy.mjs";
import {
  PHALA_EXACT_SDK_CALL_SEQUENCE,
  PHALA_EXECUTION_ORDER,
} from "./phala-production-executor-core.mjs";
import {
  PHALA_PRODUCTION_EXECUTION_FAILED_CODE,
  phalaProductionBootstrapStatus,
} from "./phala-production-executor.mjs";

const directory = path.dirname(fileURLToPath(import.meta.url));
const bootstrapPath = path.join(directory, "phala-production-executor.mjs");
const adapterPath = path.join(directory, "phala-production-sdk-adapter.mjs");
const runtimePath = path.join(directory, "phala-production-executor-runtime.mjs");

function run(args, env = process.env) {
  return spawnSync(process.execPath, [bootstrapPath, ...args], {
    cwd: path.resolve(directory, ".."),
    encoding: "utf8",
    env,
    timeout: 10_000,
  });
}

test("bootstrap status exposes the exact available executor without widening later authorities", () => {
  const status = phalaProductionBootstrapStatus();
  assert.equal(status.availability, true);
  assert.equal(status.reason_code, null);
  assert.deepEqual(status.blocker_codes, PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES);
  assert.deepEqual(status.blocker_codes, []);
  assert.deepEqual(status.bootstrap_blocker_codes, []);
  assert.deepEqual(
    status.bootstrap_blocker_codes,
    PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
  );
  assert.deepEqual(
    status.implemented_control_codes,
    PHALA_PRODUCTION_BOOTSTRAP_IMPLEMENTED_CONTROL_CODES,
  );
  assert.ok(status.implemented_control_codes.length > 0);
  assert.deepEqual(
    status.post_measurement_blocker_codes,
    PHALA_PRODUCTION_POST_MEASUREMENT_BLOCKER_CODES,
  );
  assert.deepEqual(
    status.live_activation_blocker_codes,
    PHALA_PRODUCTION_LIVE_ACTIVATION_BLOCKER_CODES,
  );
  assert.ok(status.live_activation_blocker_codes.includes(
    PHALA_LIVE_ACTIVATION_AUTHORITY_MISSING,
  ));
  assert.deepEqual(status.execution_order, PHALA_EXECUTION_ORDER);
  assert.deepEqual(status.exact_sdk_call_sequence, PHALA_EXACT_SDK_CALL_SEQUENCE);
  assert.equal(status.execution_module, "scripts/phala-production-executor-runtime.mjs");
  assert.equal(status.phala_sdk_imported, false);
  assert.equal(status.credential_file_read, false);
  assert.equal(status.process_environment_credential_read, false);
  assert.equal(status.network_call_performed, false);
  assert.equal(status.phala_mutation_performed, false);
  assert.equal(status.caller_supplied_client_accepted, false);
  assert.equal(status.caller_supplied_callback_accepted, false);
  assert.equal(status.automatic_retry_authorized, false);
  assert.equal(status.redirects_authorized, false);
  assert.equal(JSON.stringify(status).includes("phak_"), false);
});

test("status and compatibility-plan commands remain read-only diagnostics", () => {
  const statusResult = run(["--status-json"]);
  assert.equal(statusResult.status, 0);
  assert.equal(statusResult.stderr, "");
  const status = JSON.parse(statusResult.stdout);
  assert.equal(status.availability, true);
  assert.equal(status.network_call_performed, false);
  assert.equal(status.phala_mutation_performed, false);

  const compatibilityResult = run(["--compatibility-plan-json"]);
  assert.equal(compatibilityResult.status, 0);
  assert.equal(compatibilityResult.stderr, "");
  const plan = JSON.parse(compatibilityResult.stdout);
  assert.deepEqual(plan.mutation_calls, []);
  assert.equal(plan.request_policy.retry, 0);
  assert.equal(plan.request_policy.redirect, "error");
  assert.equal(plan.automatic_version_selection, false);
});

test("invalid execution requests fail before credential or network access and reveal no details", (t) => {
  const canary = ["phak_", "executor_canary_must_not_be_printed"].join("");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-production-executor-"));
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  const looseRequest = path.join(temp, "loose-request.json");
  fs.writeFileSync(looseRequest, "{}\n", { mode: 0o644 });
  fs.chmodSync(looseRequest, 0o644);

  for (const args of [
    ["--execute-request", "relative-request.json"],
    ["--execute-request", looseRequest],
    ["--execute-request"],
    ["--status-json", "--execute-request"],
    ["--compatibility-plan-json", looseRequest],
  ]) {
    const result = run(args, {
      ...process.env,
      PHALA_CLOUD_API_KEY: canary,
      PHALA_CLOUD_API_PREFIX: "https://evil.invalid",
      DEBUG: "*",
    });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, `${PHALA_PRODUCTION_EXECUTION_FAILED_CODE}\n`);
    assert.equal(`${result.stdout}${result.stderr}`.includes(canary), false);
    assert.equal(`${result.stdout}${result.stderr}`.includes("evil.invalid"), false);
    assert.equal(`${result.stdout}${result.stderr}`.includes(looseRequest), false);
  }
});

test("bootstrap delegates only canonical private requests to the reviewed runtime", () => {
  const bootstrap = fs.readFileSync(bootstrapPath, "utf8");
  const adapter = fs.readFileSync(adapterPath, "utf8");
  const runtime = fs.readFileSync(runtimePath, "utf8");
  assert.doesNotMatch(bootstrap, /from\s+["']@phala\/cloud["']/);
  assert.doesNotMatch(bootstrap, /node:child_process|execFile|spawn\s*\(/);
  assert.doesNotMatch(bootstrap, /PHALA_CLOUD_API_KEY|--private-key/);
  assert.match(bootstrap, /await import\("\.\/phala-production-executor-runtime\.mjs"\)/);
  assert.match(bootstrap, /\(before\.mode & 0o777\) !== 0o600/);
  assert.match(bootstrap, /O_NOFOLLOW/);
  assert.doesNotMatch(adapter, /node:child_process|execFile|spawn\s*\(/);
  assert.doesNotMatch(adapter, /phala\s+deploy|--prepare-only|--private-key/);
  assert.match(adapter, /export async function createPinnedPhalaProductionSdkAdapter\(value\)/);
  assert.doesNotMatch(adapter, /testAdapter|fakeClient|callerClient|callerTransport/i);
  assert.match(adapter, /assertProductionExecutionPolicyAvailable\(\);/);
  assert.match(runtime, /createPinnedPhalaProductionSdkAdapter/);
  assert.match(runtime, /persistProductionExecutionReplay/);
  assert.match(runtime, /registerProvenanceVerifiedCompletedPhalaExecutorState/);
});

test("bootstrap rejects every legacy, widened, empty, or malformed operation", () => {
  for (const args of [
    ["--execute"],
    ["--prove-sealed"],
    ["--api-key-file", "/tmp/key"],
    ["--target-authority", "/tmp/authority.json"],
    ["--status-json", "--execute"],
    ["--help", "extra"],
    [],
  ]) {
    const result = run(args);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, `${PHALA_PRODUCTION_EXECUTION_FAILED_CODE}\n`);
  }
});
