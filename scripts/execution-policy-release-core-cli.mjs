#!/usr/bin/env node

import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MAX_EXECUTION_POLICY_RELEASE_CORE_BYTES,
  canonicalFinalReleaseAuthorityCoreArtifactText,
  executionPolicyReleaseCoreDigest,
  normalizeExecutionPolicyReleaseCore,
} from "./execution-policy-release-core.mjs";

const modulePath = fileURLToPath(new URL(
  "./execution-policy-release-core-cli.mjs",
  import.meta.url,
));

const MAX_ARTIFACT_BYTES = MAX_EXECUTION_POLICY_RELEASE_CORE_BYTES * 3;

function usage() {
  return [
    "Usage:",
    "  node scripts/execution-policy-release-core-cli.mjs \\",
    "    --artifact /absolute/path/execution-policy-release-core.json \\",
    "    --release-sha <40 lowercase hex> \\",
    "    --operator 0x<address> \\",
    "    --anchor 0x<address> \\",
    "    --anchor-code-hash 0x<bytes32> \\",
    "    --writer 0x<address>",
    "",
    "The artifact must be canonical normalized pretty JSON with one final newline.",
    "On success stdout contains only the 0x-prefixed CVM-launch-intent writer commitment",
    "already cross-validated by the final-authority core.",
  ].join("\n");
}

function stableStatEqual(before, after) {
  return ["dev", "ino", "size", "mtimeNs", "ctimeNs"]
    .every((key) => before[key] === after[key]);
}

export async function readCanonicalExecutionPolicyReleaseCoreArtifact(filePath) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)) {
    throw new Error("release-core artifact path must be absolute");
  }
  const resolved = path.resolve(filePath);
  const resolvedBefore = await realpath(resolved).catch(() => {
    throw new Error("release-core artifact is unavailable");
  });
  if (resolvedBefore !== resolved) {
    throw new Error("release-core artifact path must not contain symbolic links");
  }

  let handle;
  try {
    handle = await open(resolved, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) throw new Error("release-core artifact must be a regular file");
    if (before.size < 2n || before.size > BigInt(MAX_ARTIFACT_BYTES)) {
      throw new Error("release-core artifact size is outside the reviewed bound");
    }
    const raw = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const resolvedAfter = await realpath(resolved);
    if (
      resolvedAfter !== resolvedBefore
      || !stableStatEqual(before, after)
      || raw.byteLength !== Number(before.size)
    ) {
      throw new Error("release-core artifact changed while it was being read");
    }

    let value;
    try {
      value = JSON.parse(raw.toString("utf8"));
    } catch {
      throw new Error("release-core artifact must contain valid JSON");
    }
    const core = normalizeExecutionPolicyReleaseCore(value);
    const canonicalArtifact = Buffer.from(
      canonicalFinalReleaseAuthorityCoreArtifactText(core),
      "utf8",
    );
    if (!raw.equals(canonicalArtifact)) {
      throw new Error(
        "release-core artifact must be canonical normalized pretty JSON with one final newline",
      );
    }
    return {
      core,
      digest: executionPolicyReleaseCoreDigest(core),
      raw,
    };
  } finally {
    await handle?.close();
  }
}

function expectedAddress(value, label) {
  const normalized = String(value || "").toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized) || /^0x0{40}$/.test(normalized)) {
    throw new Error(`${label} must be a nonzero Ethereum address`);
  }
  return normalized;
}

function expectedBytes32(value, label) {
  const normalized = String(value || "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(normalized) || /^0x0{64}$/.test(normalized)) {
    throw new Error(`${label} must be a nonzero bytes32 value`);
  }
  return normalized;
}

export function assertReleaseCoreMatchesCeremony(core, expected) {
  const releaseSha = String(expected?.releaseSha || "");
  if (!/^[0-9a-f]{40}$/.test(releaseSha) || core.release_sha !== releaseSha) {
    throw new Error("release-core artifact does not match RELEASE_SHA");
  }
  if (core.operator_address !== expectedAddress(expected?.operator, "operator")) {
    throw new Error("release-core artifact does not match DEPLOYMENT_OPERATOR");
  }
  const anchor = core.execution_policy.rollback_anchor_target;
  if (anchor.contract_address !== expectedAddress(expected?.anchor, "anchor")) {
    throw new Error("release-core artifact does not match EXECUTION_POLICY_ANCHOR_ADDRESS");
  }
  if (
    anchor.runtime_code_hash
    !== expectedBytes32(expected?.anchorCodeHash, "anchor code hash")
  ) {
    throw new Error(
      "release-core artifact does not match EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH",
    );
  }
  if (anchor.writer_address !== expectedAddress(expected?.writer, "writer")) {
    throw new Error("release-core artifact does not match EXECUTION_POLICY_ANCHOR_WRITER");
  }
}

export function executionPolicyWriterReleaseCommitment(core) {
  const commitment = core?.execution_policy?.rollback_anchor_target
    ?.writer_release_commitment;
  return expectedBytes32(commitment, "writer release commitment");
}

export function parseArgs(argv) {
  const names = new Map([
    ["--artifact", "artifact"],
    ["--release-sha", "releaseSha"],
    ["--operator", "operator"],
    ["--anchor", "anchor"],
    ["--anchor-code-hash", "anchorCodeHash"],
    ["--writer", "writer"],
  ]);
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--help") {
      if (argv.length !== 1) throw new Error("--help must be used alone");
      return { help: true };
    }
    const key = names.get(flag);
    if (!key) throw new Error(`unknown argument: ${flag}`);
    if (Object.hasOwn(parsed, key)) throw new Error(`duplicate argument: ${flag}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${flag}`);
    parsed[key] = value;
    index += 1;
  }
  for (const [flag, key] of names) {
    if (!Object.hasOwn(parsed, key)) throw new Error(`${flag} is required`);
  }
  if (!path.isAbsolute(parsed.artifact)) {
    throw new Error("--artifact must be an absolute path");
  }
  return parsed;
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) {
    console.error(usage());
    return;
  }
  const artifact = await readCanonicalExecutionPolicyReleaseCoreArtifact(args.artifact);
  assertReleaseCoreMatchesCeremony(artifact.core, args);
  console.log(executionPolicyWriterReleaseCommitment(artifact.core));
}

if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
