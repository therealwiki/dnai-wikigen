#!/usr/bin/env node

import { spawnSync } from "node:child_process";

import {
  WEB_ROOT,
  loadAndAssertPortableWebTestManifest,
} from "./portable-web-test-manifest.mjs";
import { assertPlainPortableWebTestProcess } from "./portable-web-test-profile.mjs";

assertPlainPortableWebTestProcess();
const manifest = loadAndAssertPortableWebTestManifest();

process.stdout.write(
  `truth: ${manifest.portable_truth_status}; operator-host files: ${manifest.operator_host_file_count}\n`,
);

const result = spawnSync(process.execPath, ["--test", ...manifest.portable], {
  cwd: WEB_ROOT,
  env: { ...process.env },
  stdio: "inherit",
});
if (result.error) throw result.error;
if (result.signal !== null || result.status !== 0) {
  throw new Error(
    `portable web test suites failed with ${result.signal || `exit ${result.status}`}`,
  );
}
