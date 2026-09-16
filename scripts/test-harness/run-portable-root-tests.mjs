#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";

import {
  ROOT,
  loadAndAssertPortableRootTestManifest,
} from "./portable-root-test-manifest.mjs";
import { assertPlainPortableTestProcess } from "./portable-root-test-profile.mjs";

assertPlainPortableTestProcess();
const manifest = loadAndAssertPortableRootTestManifest();

process.stdout.write(
  `truth: ${manifest.portable_truth_status}; operator-host files: ${manifest.operator_host_file_count}\n`,
);

for (const [label, args] of [
  [
    "unhooked frozen operator-authority rejection probe",
    [path.join(ROOT, "scripts", "test-harness", "operator-authority-fail-closed-probe.mjs")],
  ],
  ["portable root test suites", ["--test", ...manifest.portable]],
]) {
  const result = spawnSync(process.execPath, args, {
    cwd: ROOT,
    env: { ...process.env },
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.signal !== null || result.status !== 0) {
    throw new Error(`${label} failed with ${result.signal || `exit ${result.status}`}`);
  }
}
