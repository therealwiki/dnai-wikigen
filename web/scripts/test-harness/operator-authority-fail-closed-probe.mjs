#!/usr/bin/env node

import assert from "node:assert/strict";
import {
  chmod,
  mkdtemp,
  realpath,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { cloudflareBuildSandbox } from "../cloudflare-build-sandbox-core.mjs";
import { assertPinnedReleaseRuntime } from "../release-runtime-pins-core.mjs";

assert.equal(process.platform, "linux");
assert.equal(process.arch, "x64");
assert.equal(process.version, "v22.23.2");
assert.notEqual(process.execPath, "/opt/homebrew/Cellar/node/24.9.0/bin/node");
assert.throws(
  () => assertPinnedReleaseRuntime(),
  /Cloudflare release Node version must be exactly v24\.9\.0/,
);

const canonicalTemporaryRoot = await realpath(tmpdir());
const buildRoot = await mkdtemp(path.join(
  canonicalTemporaryRoot,
  "dnai-generic-linux-sandbox-rejection-",
));
await chmod(buildRoot, 0o700);
try {
  await assert.rejects(
    cloudflareBuildSandbox({ buildRoot }),
    /requires the reviewed macOS sandbox-exec boundary/,
  );
} finally {
  await rm(buildRoot, { recursive: true, force: true });
}

process.stdout.write(
  "truth: generic Linux rejected frozen Darwin Node/npm and sandbox authority\n",
);
