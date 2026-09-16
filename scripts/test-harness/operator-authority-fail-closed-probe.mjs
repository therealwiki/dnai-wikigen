#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  assertPinnedCastSignatureVerifier,
} from "../release-authority-signature-verifier.mjs";
import {
  verifyPinnedSevenCvmIsolatedRuntimeEnvironment,
} from "../phala-seven-cvm-verifier-evidence.mjs";
import * as releaseReviewerCli from "../release-reviewer-authority-cli.mjs";
import { ROOT } from "./portable-root-test-manifest.mjs";
import { assertPlainPortableTestProcess } from "./portable-root-test-profile.mjs";

// This is the semantic identity emitted by Foundry's official v1.5.1 Linux
// release asset. It is intentionally distinct from the frozen operator-host
// authority (1.5.1-stable plus a reviewed Darwin binary digest). Matching this
// label only makes the generic-CI rejection probe reproducible; it never grants
// signature-verification authority.
export const GENERIC_CI_NON_AUTHORIZING_CAST = Object.freeze({
  build_profile: "maxperf",
  commit_sha: "b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2",
  version: "1.5.1-v1.5.1",
});
const GENERIC_CI_CAST_SHA256 =
  "7b25a9c61dac49a0718ba3c2d37ba638014f3baf35739777b2d809780914e91d";

function assertExactGenericCiCast() {
  const castPath = String(process.env.DNAI_GENERIC_CI_CAST_PATH || "");
  if (!path.isAbsolute(castPath)
    || path.resolve(castPath) !== castPath
    || fs.realpathSync.native(castPath) !== castPath) {
    throw new Error("generic-CI cast path is not one canonical absolute executable");
  }
  const named = fs.lstatSync(castPath, { bigint: true });
  const expectedUid = typeof process.geteuid === "function"
    ? BigInt(process.geteuid())
    : named.uid;
  if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n
    || named.uid !== expectedUid || Number(named.mode & 0o777n) !== 0o755) {
    throw new Error("generic-CI cast is not one owner-controlled regular executable");
  }
  const descriptor = fs.openSync(
    castPath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ["dev", "ino", "size", "nlink", "uid", "gid", "mode"]) {
      if (before[field] !== named[field]) {
        throw new Error("generic-CI cast changed while opening");
      }
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of [
      "dev", "ino", "size", "nlink", "uid", "gid", "mode", "mtimeNs", "ctimeNs",
    ]) {
      if (before[field] !== after[field]) {
        throw new Error("generic-CI cast changed during verification");
      }
    }
    if (createHash("sha256").update(bytes).digest("hex") !== GENERIC_CI_CAST_SHA256) {
      throw new Error("generic-CI cast bytes do not match official Foundry v1.5.1");
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return castPath;
}

assertPlainPortableTestProcess();
if (process.platform !== "linux") {
  throw new Error("generic-CI operator-authority rejection probe requires Linux");
}

const castPath = assertExactGenericCiCast();
const castVersion = spawnSync(castPath, ["--version"], {
  encoding: "utf8",
  env: {
    HOME: process.env.HOME,
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
    PATH: "/usr/bin:/bin",
  },
  maxBuffer: 32 * 1024,
  timeout: 15_000,
});
const castOutput = `${castVersion.stdout || ""}\n${castVersion.stderr || ""}`;
if (castVersion.error || castVersion.status !== 0
  || !castOutput.includes(`cast Version: ${GENERIC_CI_NON_AUTHORIZING_CAST.version}`)
  || !castOutput.includes(`Commit SHA: ${GENERIC_CI_NON_AUTHORIZING_CAST.commit_sha}`)
  || !castOutput.includes(`Build Profile: ${GENERIC_CI_NON_AUTHORIZING_CAST.build_profile}`)) {
  throw new Error("generic Linux cast does not match the pinned non-authorizing CI identity");
}

let castFailure = "";
try {
  assertPinnedCastSignatureVerifier();
  throw new Error("generic Linux unexpectedly satisfied frozen operator cast authority");
} catch (error) {
  castFailure = String(error?.message || error);
  if (/unexpectedly satisfied/.test(castFailure)
    || !/bytes do not match the reviewed SHA-256/.test(castFailure)) {
    throw error;
  }
}

let dcapFailure = "";
try {
  verifyPinnedSevenCvmIsolatedRuntimeEnvironment();
  throw new Error("generic Linux unexpectedly satisfied frozen operator DCAP authority");
} catch (error) {
  dcapFailure = String(error?.message || error);
  if (/unexpectedly satisfied/.test(dcapFailure)
    || !/outside the frozen Darwin arm64 authority/.test(dcapFailure)) {
    throw error;
  }
}

const facadeUrl = pathToFileURL(
  path.join(ROOT, "scripts", "release-authority-signature-verifier.mjs"),
).href;
if (Object.keys(releaseReviewerCli).some((key) => /PORTABLE|FIXTURE/.test(key))) {
  throw new Error("production release-reviewer CLI import graph exposed a fixture export");
}
const productionCli = spawnSync(process.execPath, [
  path.join(ROOT, "scripts", "release-reviewer-authority-cli.mjs"),
  "--help",
], {
  cwd: ROOT,
  encoding: "utf8",
  env: { ...process.env },
  maxBuffer: 32 * 1024,
  timeout: 15_000,
});
if (productionCli.error || productionCli.status !== 0 || productionCli.stderr !== ""
  || productionCli.stdout !== `${releaseReviewerCli.RELEASE_REVIEWER_AUTHORITY_CLI_USAGE}\n`) {
  throw new Error("unhooked production release-reviewer CLI import graph drifted");
}
const cliProbe = spawnSync(process.execPath, [
  "--input-type=module",
  "--eval",
  [
    `const facade = await import(${JSON.stringify(facadeUrl)});`,
    `if (Object.keys(facade).some((key) => /PORTABLE|FIXTURE/.test(key)))`,
    `  throw new Error("production facade exposed a portable authority");`,
    `try {`,
    `  facade.assertPinnedCastSignatureVerifier();`,
    `  throw new Error("unhooked CLI satisfied frozen cast authority");`,
    `} catch (error) {`,
    `  if (/satisfied frozen/.test(error.message)) throw error;`,
    `  if (!/bytes do not match the reviewed SHA-256/.test(error.message)) throw error;`,
    `}`,
  ].join("\n"),
], {
  cwd: ROOT,
  encoding: "utf8",
  env: { ...process.env },
  maxBuffer: 32 * 1024,
  timeout: 15_000,
});
if (cliProbe.error || cliProbe.status !== 0 || cliProbe.stderr !== "") {
  throw new Error(`unhooked production CLI authority probe failed: ${cliProbe.stderr}`);
}

process.stdout.write(`${JSON.stringify({
  schema: "dnai.generic-ci-operator-authority-rejection.v1",
  truth_status:
    "generic_linux_rejected_by_real_frozen_cast_dcap_and_unhooked_cli_authorities",
  cast_failure: castFailure,
  dcap_failure: dcapFailure,
  production_cli_import_graph_unhooked: true,
  portable_authority_injected: false,
})}\n`);
