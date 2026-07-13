#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

function usage() {
  console.error(
    [
      "Usage:",
      "  node scripts/redeploy-phala-cvm.mjs \\",
      "    --app-id <phala-app-id> \\",
      "    --compose <docker-compose-file> \\",
      "    --runtime-env <env-file> \\",
      "    [--api-env .env] \\",
      "    [--runtime-env-policy compose-refs|explicit|all] \\",
      "    [--runtime-env-allow KEY] \\",
      "    [--runtime-env-allow-file <key-file>] \\",
      "    [--self-compose-hash-env KEY] \\",
      "    [--print-runtime-env-keys] \\",
      "    [--wait-seconds 300]",
    ].join("\n"),
  );
}

export function parseArgs(argv) {
  const args = {
    apiEnv: ".env",
    runtimeEnvPolicy: "compose-refs",
    runtimeEnvAllow: [],
    runtimeEnvAllowFiles: [],
    selfComposeHashEnv: "",
    printRuntimeEnvKeys: false,
    waitSeconds: 300,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      throw new Error(`unexpected argument: ${arg}`);
    }

    const key = arg.slice(2);
    if (key === "help") {
      args.help = true;
      continue;
    }
    if (key === "print-runtime-env-keys") {
      args.printRuntimeEnvKeys = true;
      continue;
    }

    const value = argv[i + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`missing value for --${key}`);
    }
    i += 1;

    switch (key) {
      case "app-id":
        args.appId = value;
        break;
      case "compose":
        args.compose = value;
        break;
      case "runtime-env":
        args.runtimeEnv = value;
        break;
      case "runtime-env-policy":
        args.runtimeEnvPolicy = value;
        break;
      case "runtime-env-allow":
        args.runtimeEnvAllow.push(value);
        break;
      case "runtime-env-allow-file":
        args.runtimeEnvAllowFiles.push(value);
        break;
      case "self-compose-hash-env":
        args.selfComposeHashEnv = requireEnvKey(value);
        break;
      case "api-env":
        args.apiEnv = value;
        break;
      case "wait-seconds":
        args.waitSeconds = Number(value);
        break;
      default:
        throw new Error(`unknown flag: --${key}`);
    }
  }

  if (!["compose-refs", "explicit", "all"].includes(args.runtimeEnvPolicy)) {
    throw new Error("--runtime-env-policy must be compose-refs, explicit, or all");
  }

  return args;
}

function stripInlineComment(value) {
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (ch === "#" && !inSingle && !inDouble) {
      const prev = i === 0 ? " " : value[i - 1];
      if (/\s/.test(prev)) {
        return value.slice(0, i).trimEnd();
      }
    }
  }

  return value;
}

function unquote(value) {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    const inner = trimmed.slice(1, -1);
    if (trimmed.startsWith('"')) {
      return inner
        .replace(/\\n/g, "\n")
        .replace(/\\r/g, "\r")
        .replace(/\\t/g, "\t")
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, "\\");
    }
    return inner.replace(/\\'/g, "'");
  }
  return trimmed;
}

export async function parseEnvFile(filePath) {
  const content = await readFile(filePath, "utf8");
  const env = new Map();

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const normalized = line.startsWith("export ") ? line.slice(7).trim() : line;
    const eqIndex = normalized.indexOf("=");
    if (eqIndex <= 0) {
      continue;
    }

    const key = normalized.slice(0, eqIndex).trim();
    const rawValue = normalized.slice(eqIndex + 1);
    env.set(key, unquote(stripInlineComment(rawValue)));
  }

  return env;
}

function requireEnvKey(key) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    throw new Error(`invalid runtime env key: ${key}`);
  }
  return key;
}

export function extractComposeEnvNames(composeText) {
  const names = [];
  const pattern = /\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}/g;
  let match;
  while ((match = pattern.exec(composeText)) !== null) {
    names.push(match[1]);
  }
  return [...new Set(names)].sort();
}

export async function parseEnvKeyFile(filePath) {
  const content = await readFile(filePath, "utf8");
  const keys = [];

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const normalized = line.startsWith("export ") ? line.slice(7).trim() : line;
    const eqIndex = normalized.indexOf("=");
    const key = (eqIndex >= 0 ? normalized.slice(0, eqIndex) : normalized).trim();
    keys.push(requireEnvKey(key));
  }

  return keys;
}

export async function selectRuntimeEnv(runtimeEnv, composeText, args) {
  const selectedKeys = [];
  const missingExplicitKeys = [];
  const composeEnvNames = extractComposeEnvNames(composeText);

  if (args.runtimeEnvPolicy === "all") {
    selectedKeys.push(...runtimeEnv.keys());
  } else if (args.runtimeEnvPolicy === "compose-refs") {
    for (const key of composeEnvNames) {
      if (runtimeEnv.has(key)) {
        selectedKeys.push(key);
      }
    }
  }

  const explicitKeys = [...(args.runtimeEnvAllow || [])].map(requireEnvKey);
  for (const filePath of args.runtimeEnvAllowFiles || []) {
    explicitKeys.push(...(await parseEnvKeyFile(filePath)));
  }
  for (const key of explicitKeys) {
    if (!runtimeEnv.has(key)) {
      missingExplicitKeys.push(key);
      continue;
    }
    selectedKeys.push(key);
  }

  if (missingExplicitKeys.length > 0) {
    throw new Error(
      "explicit runtime env keys missing from runtime env file: "
        + missingExplicitKeys.join(","),
    );
  }

  const dedupedKeys = [...new Set(selectedKeys)];
  if (dedupedKeys.length === 0) {
    throw new Error(
      "no runtime env keys selected; add --runtime-env-allow KEY or use "
        + "--runtime-env-policy all for legacy broad updates",
    );
  }

  return {
    entries: dedupedKeys.map((key) => ({ key, value: runtimeEnv.get(key) })),
    composeEnvNames,
    policy: args.runtimeEnvPolicy,
  };
}

export function runtimeEnvKeyHash(envEntries) {
  const keys = envEntries.map((entry) => entry.key).sort();
  return createHash("sha256").update(keys.join("\n")).digest("hex");
}

export function bindSelfComposeHashEnv(envEntries, key, composeHash) {
  const normalizedKey = requireEnvKey(key);
  if (!/^[0-9a-f]{64}$/i.test(composeHash)) {
    throw new Error("self compose hash must be a 32-byte hex string without 0x prefix");
  }
  let found = false;
  const updated = envEntries.map((entry) => {
    if (entry.key !== normalizedKey) {
      return entry;
    }
    found = true;
    return { key: entry.key, value: composeHash.toLowerCase() };
  });
  if (!found) {
    throw new Error(`self compose hash env key not selected: ${normalizedKey}`);
  }
  return updated;
}

async function loadCloudSdk() {
  const npmRoot = execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim();
  const sdkPath = path.join(
    npmRoot,
    "phala",
    "node_modules",
    "@phala",
    "cloud",
    "dist",
    "index.mjs",
  );
  return import(pathToFileURL(sdkPath).href);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    usage();
    return;
  }

  if (!args.appId || !args.compose || !args.runtimeEnv) {
    usage();
    throw new Error("missing required arguments");
  }
  if (!Number.isFinite(args.waitSeconds) || args.waitSeconds < 0) {
    throw new Error("--wait-seconds must be a non-negative number");
  }

  const apiEnv = await parseEnvFile(args.apiEnv);
  const runtimeEnv = await parseEnvFile(args.runtimeEnv);
  const apiKey = process.env.PHALA_CLOUD_API_KEY || apiEnv.get("PHALA_CLOUD_API_KEY");

  if (!apiKey) {
    throw new Error(`PHALA_CLOUD_API_KEY not found in ${args.apiEnv} or process env`);
  }
  if (runtimeEnv.size === 0) {
    throw new Error(`no runtime env vars found in ${args.runtimeEnv}`);
  }

  const composeText = await readFile(args.compose, "utf8");
  const selectedRuntimeEnv = await selectRuntimeEnv(runtimeEnv, composeText, args);
  let envEntries = selectedRuntimeEnv.entries;
  const { createClient, encryptEnvVars } = await loadCloudSdk();
  const client = createClient({
    apiKey,
    version: "2026-01-21",
    baseURL: "https://cloud-api.phala.com/api/v1",
  });

  const currentInfo = await client.safeGetCvmInfo({ app_id: args.appId });
  if (!currentInfo.success) {
    throw new Error(`failed to fetch CVM info: ${JSON.stringify(currentInfo.error)}`);
  }

  const currentCompose = await client.getCvmComposeFile({ app_id: args.appId });
  const envPubkey =
    currentCompose.env_pubkey || currentInfo.data.kms_info?.encrypted_env_pubkey;
  if (!envPubkey) {
    throw new Error("current CVM info is missing the encrypted env public key");
  }

  const nextCompose = {
    ...currentCompose,
    docker_compose_file: composeText,
    allowed_envs: envEntries.map((entry) => entry.key),
  };

  const provisioned = await client.provisionCvmComposeFileUpdate({
    app_id: args.appId,
    app_compose: nextCompose,
    update_env_vars: true,
  });

  if (args.selfComposeHashEnv) {
    envEntries = bindSelfComposeHashEnv(
      envEntries,
      args.selfComposeHashEnv,
      provisioned.compose_hash,
    );
  }

  const encryptedEnv = await encryptEnvVars(envEntries, envPubkey);
  await client.commitCvmComposeFileUpdate({
    app_id: args.appId,
    compose_hash: provisioned.compose_hash,
    encrypted_env: encryptedEnv,
    env_keys: envEntries.map((entry) => entry.key),
    update_env_vars: true,
  });

  console.log(`app_id=${args.appId}`);
  console.log(`cvm_id=${currentInfo.data.id}`);
  console.log(`compose_hash=${provisioned.compose_hash}`);
  console.log(`runtime_env_policy=${selectedRuntimeEnv.policy}`);
  console.log(`runtime_env_key_count=${envEntries.length}`);
  console.log(`runtime_env_keys_sha256=${runtimeEnvKeyHash(envEntries)}`);
  if (args.selfComposeHashEnv) {
    console.log(`self_compose_hash_env=${args.selfComposeHashEnv}`);
  }
  if (args.printRuntimeEnvKeys) {
    console.log(`runtime_env_keys=${envEntries.map((entry) => entry.key).join(",")}`);
  }

  if (args.waitSeconds === 0) {
    return;
  }

  const deadline = Date.now() + args.waitSeconds * 1000;
  while (Date.now() < deadline) {
    const compose = await client.safeGetCvmComposeFile({ app_id: args.appId });
    const state = await client.safeGetCvmState({ app_id: args.appId });

    const liveHash = compose.success ? compose.data.getHash() : "unavailable";
    const stateStatus = state.success ? state.data.status : "unavailable";
    const bootProgress = state.success ? state.data.boot_progress : "unavailable";

    console.log(
      `poll live_hash=${liveHash} state=${stateStatus} boot_progress=${bootProgress}`,
    );

    if (compose.success && liveHash === provisioned.compose_hash) {
      return;
    }

    await sleep(5000);
  }

  throw new Error(
    `timed out waiting for compose hash ${provisioned.compose_hash} to become active`,
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.stack || error.message : String(error));
    process.exit(1);
  });
}
