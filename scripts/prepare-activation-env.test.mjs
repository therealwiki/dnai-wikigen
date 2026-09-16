import assert from "node:assert/strict";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { parseEnvText } from "./activation-preflight-core.mjs";
import {
  ACTIVATION_ENV_SCHEMA,
  ActivationEnvError,
  FORBIDDEN_LEGACY_PRIVATE_KEY_NAMES,
  INTERNAL_ACTIVATION_SECRET_GROUPS,
  INTERNAL_ACTIVATION_SECRET_KEYS,
  prepareActivationEnvironment,
} from "./prepare-activation-env-core.mjs";
import {
  exitCodeForSummary,
  parseArgs,
  summaryLines,
  usage,
} from "./prepare-activation-env.mjs";

const EXPECTED_SECRET_KEYS = [
  "TINKER_DILIGENCE_QVL_AUTH_TOKEN",
  "TINKER_ARENA_WORKER_QVL_AUTH_TOKEN",
  "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN",
  "TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN",
  "TINKER_COMPUTE_METERING_QVL_AUTH_TOKEN",
  "METERING_QVL_AUTH_TOKEN",
  "METERING_AUTH_TOKEN",
  "TINKER_COMPUTE_METERING_AUTH_TOKEN",
  "NEKO_PASSWORD",
  "NEKO_PASSWORD_ADMIN",
];

const TEMPLATE = [
  "# fixture",
  "PRESERVED_DEFAULT=hello",
  "EXTERNAL_SECRET=",
  "QVL_AUTH_TOKEN=",
  ...EXPECTED_SECRET_KEYS.map((key) => `${key}=`),
  "LAST_DEFAULT=42",
  "",
].join("\n");

async function fixture({ templateText = TEMPLATE, targetText, targetMode = 0o600 } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), "dnai-activation-env-"));
  const templatePath = path.join(root, "example.env");
  const targetPath = path.join(root, ".env");
  await writeFile(templatePath, templateText, { mode: 0o644 });
  if (targetText !== undefined) {
    await writeFile(targetPath, targetText, { mode: targetMode });
    await chmod(targetPath, targetMode);
  }
  return { root, templatePath, targetPath };
}

function deterministicRng() {
  let calls = 0;
  const randomBytes = (size) => {
    calls += 1;
    return Buffer.alloc(size, calls);
  };
  randomBytes.calls = () => calls;
  return randomBytes;
}

function options(value, overrides = {}) {
  return {
    repoRoot: value.root,
    templatePath: value.templatePath,
    targetPath: value.targetPath,
    trackedCheck: async () => false,
    ...overrides,
  };
}

function valuesFrom(text) {
  return parseEnvText(text);
}

test("the helper is pinned to exactly ten preflight credentials in eight trust groups", () => {
  assert.deepEqual(INTERNAL_ACTIVATION_SECRET_KEYS, EXPECTED_SECRET_KEYS);
  assert.equal(INTERNAL_ACTIVATION_SECRET_KEYS.length, 10);
  assert.equal(INTERNAL_ACTIVATION_SECRET_GROUPS.length, 8);
  assert.deepEqual(FORBIDDEN_LEGACY_PRIVATE_KEY_NAMES, [
    "JUDGE_PRIVATE_KEY",
    "KMS_PRIVATE_KEY",
  ]);
  for (const forbidden of [
    "ETHERSCAN_API_KEY",
    "PHALA_CLOUD_API_KEY",
    "OPENROUTER_API_KEY",
    "GITHUB_TOKEN",
    "QVL_AUTH_TOKEN",
  ]) {
    assert.equal(INTERNAL_ACTIVATION_SECRET_KEYS.includes(forbidden), false);
  }
});

test("example.env carries every internal activation field exactly once", async () => {
  const repositoryTemplate = await readFile(
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "example.env"),
    "utf8",
  );
  for (const key of INTERNAL_ACTIVATION_SECRET_KEYS) {
    assert.equal(
      repositoryTemplate.split(/\r?\n/).filter((line) => new RegExp(`^${key}\\s*=`).test(line)).length,
      1,
      key,
    );
  }
});

test("absent target is created atomically at 0600 with ten fields and eight random values", async () => {
  const value = await fixture();
  const randomBytes = deterministicRng();
  const summary = await prepareActivationEnvironment(options(value, {
    generateInternalSecrets: true,
    randomBytes,
  }));
  const targetText = await readFile(value.targetPath, "utf8");
  const env = valuesFrom(targetText);
  const generated = INTERNAL_ACTIVATION_SECRET_KEYS.map((key) => env[key]);

  assert.equal(summary.schema, ACTIVATION_ENV_SCHEMA);
  assert.equal(summary.status, "updated");
  assert.equal(summary.wrote, true);
  assert.equal(summary.secretFieldsPrepared, 10);
  assert.equal(summary.randomSecretsGenerated, 8);
  assert.equal(randomBytes.calls(), 8);
  assert.equal((await stat(value.targetPath)).mode & 0o7777, 0o600);
  assert.equal(env.PRESERVED_DEFAULT, "hello");
  assert.equal(env.EXTERNAL_SECRET, "");
  assert.equal(env.QVL_AUTH_TOKEN, "");
  for (const secret of generated) assert.match(secret, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(env.TINKER_COMPUTE_METERING_QVL_AUTH_TOKEN, env.METERING_QVL_AUTH_TOKEN);
  assert.equal(env.METERING_AUTH_TOKEN, env.TINKER_COMPUTE_METERING_AUTH_TOKEN);
  assert.equal(new Set(generated).size, 8);
  assert.notEqual(env.NEKO_PASSWORD, env.NEKO_PASSWORD_ADMIN);
  assert.equal(env.NEKO_PASSWORD === "neko" || env.NEKO_PASSWORD_ADMIN === "admin", false);
  assert.deepEqual(
    (await lstat(value.root)).isDirectory(),
    true,
  );
  const names = await (await import("node:fs/promises")).readdir(value.root);
  assert.deepEqual(names.filter((name) => name.endsWith(".tmp")), []);
});

test("existing values and inert shell-shaped bytes are preserved while missing defaults sync", async () => {
  const existing = [
    "# operator-owned text",
    "PRESERVED_DEFAULT=operator-choice",
    "UNKNOWN_VALUE=$(touch /tmp/must-not-run) # inert",
    "EXTERNAL_SECRET='quoted#secret'",
    "",
  ].join("\n");
  const value = await fixture({ targetText: existing });
  const summary = await prepareActivationEnvironment(options(value));
  const result = await readFile(value.targetPath, "utf8");

  assert.equal(summary.status, "updated");
  assert.equal(summary.secretFieldsPrepared, 0);
  assert.equal(result.startsWith(existing), true);
  assert.equal(valuesFrom(result).PRESERVED_DEFAULT, "operator-choice");
  assert.equal(valuesFrom(result).UNKNOWN_VALUE, "$(touch /tmp/must-not-run)");
  assert.equal(valuesFrom(result).EXTERNAL_SECRET, "quoted#secret");
  assert.equal(valuesFrom(result).LAST_DEFAULT, "42");
});

test("a second generated run is byte-idempotent, does not rewrite, and consumes no entropy", async () => {
  const value = await fixture();
  await prepareActivationEnvironment(options(value, {
    generateInternalSecrets: true,
    randomBytes: deterministicRng(),
  }));
  const before = await readFile(value.targetPath);
  const beforeStat = await stat(value.targetPath);
  const randomBytes = deterministicRng();
  const summary = await prepareActivationEnvironment(options(value, {
    generateInternalSecrets: true,
    randomBytes,
  }));
  const after = await readFile(value.targetPath);
  const afterStat = await stat(value.targetPath);

  assert.equal(summary.status, "ready");
  assert.equal(summary.wrote, false);
  assert.equal(randomBytes.calls(), 0);
  assert.deepEqual(after, before);
  assert.equal(afterStat.ino, beforeStat.ino);
  assert.equal(afterStat.mtimeMs, beforeStat.mtimeMs);
});

test("one existing alias is copied without new entropy and mismatched aliases fail unchanged", async () => {
  const existingSecret = "x".repeat(43);
  const partial = TEMPLATE.replace(
    "TINKER_COMPUTE_METERING_QVL_AUTH_TOKEN=",
    `TINKER_COMPUTE_METERING_QVL_AUTH_TOKEN=${existingSecret}`,
  );
  const value = await fixture({ targetText: partial });
  const randomBytes = deterministicRng();
  const summary = await prepareActivationEnvironment(options(value, {
    generateInternalSecrets: true,
    randomBytes,
  }));
  const env = valuesFrom(await readFile(value.targetPath, "utf8"));
  assert.equal(env.METERING_QVL_AUTH_TOKEN, existingSecret);
  assert.equal(summary.randomSecretsGenerated, 7);
  assert.equal(randomBytes.calls(), 7);

  const mismatchText = (await readFile(value.targetPath, "utf8")).replace(
    `METERING_QVL_AUTH_TOKEN=${existingSecret}`,
    `METERING_QVL_AUTH_TOKEN=${"y".repeat(43)}`,
  );
  await writeFile(value.targetPath, mismatchText);
  await chmod(value.targetPath, 0o600);
  const before = await readFile(value.targetPath);
  await assert.rejects(
    prepareActivationEnvironment(options(value, { generateInternalSecrets: true })),
    (error) => error instanceof ActivationEnvError && error.code === "alias_mismatch",
  );
  assert.deepEqual(await readFile(value.targetPath), before);
});

test("unsafe, reused, default, and cross-domain existing secret values fail closed", async () => {
  const cases = [
    TEMPLATE.replace("NEKO_PASSWORD=", "NEKO_PASSWORD=neko"),
    TEMPLATE
      .replace("NEKO_PASSWORD=", `NEKO_PASSWORD=${"z".repeat(43)}`)
      .replace("NEKO_PASSWORD_ADMIN=", `NEKO_PASSWORD_ADMIN=${"z".repeat(43)}`),
    TEMPLATE.replace("METERING_AUTH_TOKEN=", "METERING_AUTH_TOKEN=short"),
  ];
  for (const targetText of cases) {
    const value = await fixture({ targetText });
    const before = await readFile(value.targetPath);
    await assert.rejects(
      prepareActivationEnvironment(options(value, { generateInternalSecrets: true })),
      (error) => error instanceof ActivationEnvError
        && ["invalid_secret", "secret_reuse"].includes(error.code),
    );
    assert.deepEqual(await readFile(value.targetPath), before);
  }
});

test("check and dry-run report drift without writing or consuming randomness", async () => {
  for (const mode of ["check", "dryRun"]) {
    const value = await fixture();
    const randomBytes = deterministicRng();
    const summary = await prepareActivationEnvironment(options(value, {
      [mode]: true,
      generateInternalSecrets: true,
      randomBytes,
    }));
    assert.equal(summary.status, "needs-update");
    assert.equal(summary.wrote, false);
    assert.equal(summary.randomSecretsGenerated, 0);
    assert.equal(randomBytes.calls(), 0);
    await assert.rejects(readFile(value.targetPath), /ENOENT/);
  }
});

test("duplicate template or target keys fail without mutation", async () => {
  const duplicateTemplate = await fixture({ templateText: `${TEMPLATE}PRESERVED_DEFAULT=again\n` });
  await assert.rejects(
    prepareActivationEnvironment(options(duplicateTemplate)),
    (error) => error instanceof ActivationEnvError && error.code === "duplicate_key",
  );

  const duplicateTarget = await fixture({
    targetText: "export FOO=first\nFOO=second\n",
  });
  const before = await readFile(duplicateTarget.targetPath);
  await assert.rejects(
    prepareActivationEnvironment(options(duplicateTarget)),
    (error) => error instanceof ActivationEnvError && error.code === "duplicate_key",
  );
  assert.deepEqual(await readFile(duplicateTarget.targetPath), before);
});

test("prohibited raw-key legacy names fail by name without exposing their values", async () => {
  const legacySecret = "NEVER_PRINT_THIS_LEGACY_SECRET";
  for (const key of FORBIDDEN_LEGACY_PRIVATE_KEY_NAMES) {
    const value = await fixture({ targetText: `${key}=${legacySecret}\n` });
    const before = await readFile(value.targetPath);
    await assert.rejects(
      prepareActivationEnvironment(options(value)),
      (error) => {
        assert.equal(error instanceof ActivationEnvError, true);
        assert.equal(error.code, "legacy_private_key");
        assert.equal(error.message.includes(key), true);
        assert.equal(error.message.includes(legacySecret), false);
        return true;
      },
    );
    assert.deepEqual(await readFile(value.targetPath), before);
  }
});

test("symlink, hard-link, directory, unsafe-mode, and tracked targets are refused", async () => {
  const symlinkFixture = await fixture();
  const elsewhere = path.join(symlinkFixture.root, "elsewhere");
  await writeFile(elsewhere, "SAFE=1\n", { mode: 0o600 });
  await symlink(elsewhere, symlinkFixture.targetPath);
  await assert.rejects(
    prepareActivationEnvironment(options(symlinkFixture)),
    (error) => error.code === "symlink",
  );

  const hardLinkFixture = await fixture({ targetText: "SAFE=1\n" });
  await link(hardLinkFixture.targetPath, path.join(hardLinkFixture.root, "second-link"));
  await assert.rejects(
    prepareActivationEnvironment(options(hardLinkFixture)),
    (error) => error.code === "hard_link",
  );

  const directoryFixture = await fixture();
  await mkdir(directoryFixture.targetPath);
  await assert.rejects(
    prepareActivationEnvironment(options(directoryFixture)),
    (error) => error.code === "non_regular",
  );

  const modeFixture = await fixture({ targetText: "SAFE=1\n", targetMode: 0o644 });
  await assert.rejects(
    prepareActivationEnvironment(options(modeFixture)),
    (error) => error.code === "unsafe_mode",
  );

  const trackedFixture = await fixture({ targetText: "SAFE=1\n" });
  await assert.rejects(
    prepareActivationEnvironment(options(trackedFixture, { trackedCheck: async () => true })),
    (error) => error.code === "tracked_target",
  );
});

test("template symlinks and malformed or oversized input fail closed", async () => {
  const linked = await fixture();
  const original = path.join(linked.root, "actual-example.env");
  await writeFile(original, TEMPLATE);
  await (await import("node:fs/promises")).unlink(linked.templatePath);
  await symlink(original, linked.templatePath);
  await assert.rejects(
    prepareActivationEnvironment(options(linked)),
    (error) => error.code === "symlink",
  );

  const nul = await fixture({ targetText: "SAFE=1\u0000BAD=2\n" });
  await assert.rejects(
    prepareActivationEnvironment(options(nul)),
    (error) => error.code === "input_nul",
  );

  const oversized = await fixture({ targetText: `SAFE=${"a".repeat(2 * 1024 * 1024)}\n` });
  await assert.rejects(
    prepareActivationEnvironment(options(oversized)),
    (error) => error.code === "input_size",
  );
});

test("concurrent target or template mutation aborts and removes the temporary file", async () => {
  for (const changed of ["target", "template"]) {
    const value = await fixture({ targetText: "PRESERVED_DEFAULT=operator\n" });
    const original = await readFile(value.targetPath);
    await assert.rejects(
      prepareActivationEnvironment(options(value, {
        beforeCommit: async () => {
          const candidate = changed === "target" ? value.targetPath : value.templatePath;
          await writeFile(candidate, `${await readFile(candidate, "utf8")}# concurrent\n`);
          if (changed === "target") await chmod(candidate, 0o600);
        },
      })),
      (error) => error.code === "concurrent_change",
    );
    if (changed === "template") assert.deepEqual(await readFile(value.targetPath), original);
    const names = await (await import("node:fs/promises")).readdir(value.root);
    assert.deepEqual(names.filter((name) => name.endsWith(".tmp")), []);
  }
});

test("RNG failure, wrong-length output, and repeated collisions preserve the target", async () => {
  const failures = [
    () => { throw new Error("secret-bearing RNG detail"); },
    () => Buffer.alloc(31),
    () => Buffer.alloc(32, 7),
  ];
  for (const [index, randomBytes] of failures.entries()) {
    const value = await fixture({ targetText: TEMPLATE });
    const before = await readFile(value.targetPath);
    await assert.rejects(
      prepareActivationEnvironment(options(value, {
        generateInternalSecrets: true,
        randomBytes,
      })),
      (error) => error instanceof ActivationEnvError
        && ["rng_failure", "rng_contract", "rng_collision"].includes(error.code),
      `case ${index}`,
    );
    assert.deepEqual(await readFile(value.targetPath), before);
  }
});

test("CLI is fixed to repository files, has exact read-only flag semantics, and emits no values", () => {
  assert.throws(() => parseArgs(["--env", "/tmp/elsewhere"]), /unknown argument/);
  assert.throws(() => parseArgs(["--example", "/tmp/elsewhere"]), /unknown argument/);
  assert.throws(() => parseArgs(["--check", "--check"]), /duplicate argument/);
  assert.throws(() => parseArgs(["--check", "--dry-run"]), /mutually exclusive/);
  assert.equal(usage().includes("repository example.env and .env"), true);

  const args = parseArgs(["--check", "--generate-internal-secrets"]);
  const summary = {
    schema: ACTIVATION_ENV_SCHEMA,
    status: "needs-update",
    changesRequired: true,
    addedKeys: 300,
    secretFieldsPrepared: 10,
    randomSecretsGenerated: 0,
    internalSecretKeyCount: 10,
    distinctSecretGroupCount: 8,
  };
  assert.equal(exitCodeForSummary(args, summary), 1);
  const rendered = summaryLines(summary).join("\n");
  assert.match(rendered, /activation_env_status=needs-update/);
  assert.match(rendered, /activation_env_internal_secret_keys=10/);
  assert.match(rendered, /activation_env_distinct_secret_groups=8/);
  assert.equal(rendered.includes("TINKER_DILIGENCE_QVL_AUTH_TOKEN"), false);
  assert.equal(exitCodeForSummary(parseArgs(["--check"]), {
    ...summary,
    status: "ready",
    changesRequired: false,
  }), 0);
});
