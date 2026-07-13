import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  bindSelfComposeHashEnv,
  extractComposeEnvNames,
  parseArgs,
  runtimeEnvKeyHash,
  selectRuntimeEnv,
} from "./redeploy-phala-cvm.mjs";

test("compose-refs policy selects only referenced runtime env keys", async () => {
  const runtimeEnv = new Map([
    ["PHALA_CLOUD_API_KEY", "phak_secret"],
    ["BASE_SEPOLIA_RPC_URL", "https://rpc.example"],
    ["ORACLE_RUNTIME_AUTH_KEY_PATH", "oracle/runtime-auth"],
    ["TINKER_DSTACK_KEY_PATH", "tinker/api_key"],
    ["TINKER_FUNDING_MODE", "manual_prefund"],
  ]);
  const composeText = [
    "services:",
    "  delegate:",
    "    environment:",
    "      TINKER_DSTACK_KEY_PATH: ${TINKER_DSTACK_KEY_PATH:-tinker/api_key}",
    "      TINKER_FUNDING_MODE: ${TINKER_FUNDING_MODE:-manual_prefund}",
    "  oracle:",
    "    environment:",
    "      ORACLE_RUNTIME_AUTH_KEY_PATH: ${ORACLE_RUNTIME_AUTH_KEY_PATH:-oracle/runtime-auth}",
  ].join("\n");

  const selected = await selectRuntimeEnv(runtimeEnv, composeText, parseArgs([
    "--app-id",
    "app",
    "--compose",
    "compose.yaml",
    "--runtime-env",
    ".env",
  ]));

  assert.deepEqual(
    selected.entries.map((entry) => entry.key),
    [
      "ORACLE_RUNTIME_AUTH_KEY_PATH",
      "TINKER_DSTACK_KEY_PATH",
      "TINKER_FUNDING_MODE",
    ],
  );
  assert.equal(selected.policy, "compose-refs");
  assert.equal(extractComposeEnvNames(composeText).length, 3);
  assert.equal(runtimeEnvKeyHash(selected.entries).length, 64);
});

test("explicit policy fails closed when requested keys are missing", async () => {
  const runtimeEnv = new Map([["TINKER_DSTACK_KEY_PATH", "tinker/api_key"]]);
  await assert.rejects(
    () => selectRuntimeEnv(
      runtimeEnv,
      "services: {}",
      parseArgs([
        "--app-id",
        "app",
        "--compose",
        "compose.yaml",
        "--runtime-env",
        ".env",
        "--runtime-env-policy",
        "explicit",
        "--runtime-env-allow",
        "MISSING_KEY",
      ]),
    ),
    /explicit runtime env keys missing/,
  );
});

test("allow-file can add explicit runtime env keys without all-env fallback", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "dnai-redeploy-test-"));
  try {
    const keyFile = path.join(dir, "runtime.keys");
    await writeFile(keyFile, "TINKER_DSTACK_KEY_PATH\n# comment\nEXTRA_ALLOWED=value\n");
    const runtimeEnv = new Map([
      ["PHALA_CLOUD_API_KEY", "phak_secret"],
      ["TINKER_DSTACK_KEY_PATH", "tinker/api_key"],
      ["EXTRA_ALLOWED", "ok"],
    ]);

    const selected = await selectRuntimeEnv(
      runtimeEnv,
      "services: {}",
      parseArgs([
        "--app-id",
        "app",
        "--compose",
        "compose.yaml",
        "--runtime-env",
        ".env",
        "--runtime-env-policy",
        "explicit",
        "--runtime-env-allow-file",
        keyFile,
      ]),
    );

    assert.deepEqual(
      selected.entries.map((entry) => entry.key),
      ["TINKER_DSTACK_KEY_PATH", "EXTRA_ALLOWED"],
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("all policy remains explicit legacy broad-env mode", async () => {
  const runtimeEnv = new Map([
    ["PHALA_CLOUD_API_KEY", "phak_secret"],
    ["TINKER_DSTACK_KEY_PATH", "tinker/api_key"],
  ]);

  const selected = await selectRuntimeEnv(
    runtimeEnv,
    "services: {}",
    parseArgs([
      "--app-id",
      "app",
      "--compose",
      "compose.yaml",
      "--runtime-env",
      ".env",
      "--runtime-env-policy",
      "all",
    ]),
  );

  assert.deepEqual(
    selected.entries.map((entry) => entry.key),
    ["PHALA_CLOUD_API_KEY", "TINKER_DSTACK_KEY_PATH"],
  );
});

test("self-compose hash env binds selected key after provision", () => {
  const entries = [
    { key: "BASE_SEPOLIA_RPC_URL", value: "https://rpc.example" },
    { key: "TINKER_ENCUMBRANCE_COMPOSE_HASH", value: "stale" },
  ];
  const keysHashBefore = runtimeEnvKeyHash(entries);
  const composeHash = "A".repeat(64);

  const updated = bindSelfComposeHashEnv(
    entries,
    "TINKER_ENCUMBRANCE_COMPOSE_HASH",
    composeHash,
  );

  assert.equal(updated[1].value, composeHash.toLowerCase());
  assert.equal(runtimeEnvKeyHash(updated), keysHashBefore);
  assert.equal(entries[1].value, "stale");
});

test("self-compose hash env fails closed for missing selected key", () => {
  assert.throws(
    () => bindSelfComposeHashEnv(
      [{ key: "BASE_SEPOLIA_RPC_URL", value: "https://rpc.example" }],
      "TINKER_ENCUMBRANCE_COMPOSE_HASH",
      "b".repeat(64),
    ),
    /self compose hash env key not selected/,
  );
});

test("self-compose hash env rejects malformed hashes", () => {
  assert.throws(
    () => bindSelfComposeHashEnv(
      [{ key: "TINKER_ENCUMBRANCE_COMPOSE_HASH", value: "stale" }],
      "TINKER_ENCUMBRANCE_COMPOSE_HASH",
      "0x" + "c".repeat(64),
    ),
    /self compose hash must be a 32-byte hex string/,
  );
});
