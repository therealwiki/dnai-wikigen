#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ActivationEnvError,
  prepareActivationEnvironment,
} from "./prepare-activation-env-core.mjs";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function usage() {
  return [
    "Usage:",
    "  node scripts/prepare-activation-env.mjs [options]",
    "",
    "Options:",
    "  --generate-internal-secrets      Fill only the ten activation bearer/password fields",
    "  --check                          Read-only; exit 1 when an update is required",
    "  --dry-run                        Read-only preview; always exit 0 when valid",
    "  --help                           Show this help",
    "",
    "Safety:",
    "  This command is fixed to repository example.env and .env. Existing values",
    "  are preserved and missing template keys are synchronized.",
    "  Writes refuse symlinks, non-regular/hard-linked/tracked targets, duplicate",
    "  keys, concurrent changes, and modes other than 0600. Secret values are",
    "  generated with 256 bits of OS entropy and are never printed.",
  ].join("\n");
}

export function parseArgs(argv) {
  const args = {
    targetPath: path.join(rootDir, ".env"),
    templatePath: path.join(rootDir, "example.env"),
    generateInternalSecrets: false,
    check: false,
    dryRun: false,
    help: false,
  };
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (seen.has(flag)) throw new ActivationEnvError("arguments", `duplicate argument: ${flag}`);
    seen.add(flag);
    if (flag === "--help") args.help = true;
    else if (flag === "--generate-internal-secrets") args.generateInternalSecrets = true;
    else if (flag === "--check") args.check = true;
    else if (flag === "--dry-run") args.dryRun = true;
    else {
      throw new ActivationEnvError("arguments", `unknown argument: ${flag}`);
    }
  }
  if (args.check && args.dryRun) {
    throw new ActivationEnvError("arguments", "--check and --dry-run are mutually exclusive");
  }
  return args;
}

export function summaryLines(summary) {
  return [
    `activation_env_schema=${summary.schema}`,
    `activation_env_status=${summary.status}`,
    `activation_env_changes_required=${summary.changesRequired}`,
    `activation_env_added_keys=${summary.addedKeys}`,
    `activation_env_secret_fields_prepared=${summary.secretFieldsPrepared}`,
    `activation_env_random_values_generated=${summary.randomSecretsGenerated}`,
    `activation_env_internal_secret_keys=${summary.internalSecretKeyCount}`,
    `activation_env_distinct_secret_groups=${summary.distinctSecretGroupCount}`,
  ];
}

export function exitCodeForSummary(args, summary) {
  return args.check && summary.changesRequired ? 1 : 0;
}

export async function main(argv = process.argv.slice(2), dependencies = {}) {
  const args = parseArgs(argv);
  if (args.help) {
    (dependencies.stdout ?? console.log)(usage());
    return 0;
  }
  const summary = await prepareActivationEnvironment({
    repoRoot: rootDir,
    ...args,
  });
  const write = dependencies.stdout ?? console.log;
  for (const line of summaryLines(summary)) write(line);
  return exitCodeForSummary(args, summary);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((exitCode) => {
    process.exitCode = exitCode;
  }).catch((error) => {
    const code = error instanceof ActivationEnvError ? error.code : "unexpected_failure";
    console.error(`activation_env_status=failed code=${code}; no secret values were printed`);
    process.exitCode = 2;
  });
}
