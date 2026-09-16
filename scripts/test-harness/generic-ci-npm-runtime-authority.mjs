import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertPinnedNpmRuntime,
} from "../../web/scripts/release-runtime-pins-core.mjs";

const PINNED_GENERIC_CI_NPM = Object.freeze({
  version: "10.9.8",
  entryCount: 2_464,
  totalBytes: 10_899_866,
  treeSha256: "6f92747e6e2eceba3212e91daa0b6df5d412956da7b59ab85119c1890623c4c0",
});

function canonicalEntrypoint() {
  if (!process.argv[1]) return false;
  return fs.realpathSync.native(process.argv[1]) === fileURLToPath(import.meta.url);
}

export function assertPinnedGenericCiNpmRuntime({
  execPath = process.execPath,
  version = process.version,
  platform = process.platform,
  arch = process.arch,
  expectedUid = typeof process.geteuid === "function" ? process.geteuid() : 0,
} = {}) {
  if (
    process.execArgv.length !== 0
    || process.argv.slice(2).length !== 0
    || platform !== "linux"
    || arch !== "x64"
    || version !== "v22.23.2"
    || !path.isAbsolute(execPath)
    || fs.realpathSync.native(execPath) !== execPath
  ) {
    throw new Error("generic CI npm authority requires ordinary pinned Node v22.23.2 Linux x64");
  }
  const nodeRoot = path.resolve(path.dirname(execPath), "..");
  const treeRoot = path.join(nodeRoot, "lib", "node_modules", "npm");
  const executableSymlink = path.join(nodeRoot, "bin", "npm");
  const executableTarget = path.join(treeRoot, "bin", "npm-cli.js");
  return assertPinnedNpmRuntime({
    expectedUid,
    normalizeDirectorySizes: true,
    pin: {
      ...PINNED_GENERIC_CI_NPM,
      executableSymlink,
      executableLinkTarget: "../lib/node_modules/npm/bin/npm-cli.js",
      executableTarget,
      treeRoot,
    },
  });
}

if (canonicalEntrypoint()) {
  assertPinnedGenericCiNpmRuntime();
}

export const __test = Object.freeze({
  PINNED_GENERIC_CI_NPM,
});
