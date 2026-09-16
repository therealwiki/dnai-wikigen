import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  OPERATOR_HOST_TEST_TRUTH,
  PORTABLE_ROOT_TEST_TRUTH,
  ROOT,
  MANIFEST_PATH,
  loadAndAssertPortableRootTestManifest,
} from "./test-harness/portable-root-test-manifest.mjs";
import {
  forbiddenPortableProfileEnvironmentNames,
} from "./test-harness/portable-root-test-profile.mjs";

const RUNNER = path.join(
  ROOT,
  "scripts",
  "test-harness",
  "run-portable-root-tests.mjs",
);

function runnerFailure({ args = [], environment = {}, execArgv = [] } = {}) {
  return spawnSync(process.execPath, [
    ...execArgv,
    RUNNER,
    ...args,
  ], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
}

function portableWrapperFailure(environment = {}) {
  return spawnSync(path.join(ROOT, "scripts", "verify-local.sh"), ["portable-ci"], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
}

function webWrapperFailure(environment = {}) {
  return spawnSync(path.join(ROOT, "scripts", "verify-local.sh"), ["web-ci"], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
}

function operatorWrapperFailure(environment = {}) {
  return spawnSync(path.join(ROOT, "scripts", "verify-local.sh"), ["operator-host"], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
}

function foundryWrapperFailure(environment = {}) {
  return spawnSync(path.join(ROOT, "scripts", "verify-local.sh"), ["foundry-ci"], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
}

function secretWrapperFailure(environment = {}) {
  return spawnSync(path.join(ROOT, "scripts", "verify-local.sh"), ["secrets"], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
}

function runExtractedCleanWorkspaceGuard(root) {
  const wrapper = fs.readFileSync(
    path.join(ROOT, "scripts", "verify-local.sh"),
    "utf8",
  );
  const projectorGuardSource = wrapper.match(
    /assert_exact_head_worktree_authority\(\)[\s\S]*?\n}/,
  )?.[0];
  const cleanGuardSource = wrapper.match(
    /assert_clean_release_test_workspace\(\)[\s\S]*?\n}/,
  )?.[0];
  assert.ok(projectorGuardSource, "HEAD projector guard source must remain extractable");
  assert.ok(cleanGuardSource, "clean workspace guard source must remain extractable");
  return spawnSync("/bin/bash", [
    "-p",
    "-c",
    [
      "set +x",
      "set -euo pipefail",
      'ROOT_DIR="$1"',
      'AUTHENTICATED_GATE_NODE_EXECUTABLE="$2"',
      'SCRIPT_PLATFORM="$(/usr/bin/uname -s)"',
      'LAST_EXACT_HEAD_WORKTREE_HEAD=""',
      projectorGuardSource,
      cleanGuardSource,
      'assert_clean_release_test_workspace "clean-workspace KAT" true',
    ].join("\n"),
    "clean-workspace-guard",
    root,
    process.execPath,
  ], {
    cwd: root,
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
}

function forgeOrdinaryIndexStatCache({ file, gitDirectory, relative }) {
  const indexPath = path.join(gitDirectory, "index");
  const index = fs.readFileSync(indexPath);
  assert.equal(index.subarray(0, 4).toString("ascii"), "DIRC");
  assert.equal(index.readUInt32BE(4), 2);
  const entryCount = index.readUInt32BE(8);
  let offset = 12;
  let found = false;
  const low32 = (value) => Number(value & 0xffff_ffffn);
  for (let entry = 0; entry < entryCount; entry += 1) {
    const flags = index.readUInt16BE(offset + 60);
    const encodedLength = flags & 0x0fff;
    const nul = index.indexOf(0, offset + 62);
    assert.ok(nul > offset + 62, "index entry path must be NUL terminated");
    const entryPath = index.subarray(offset + 62, nul).toString("utf8");
    if (entryPath === relative) {
      const stat = fs.statSync(file, { bigint: true });
      const seconds = 1_000_000_000n;
      const fields = [
        stat.ctimeNs / seconds,
        stat.ctimeNs % seconds,
        stat.mtimeNs / seconds,
        stat.mtimeNs % seconds,
        stat.dev,
        stat.ino,
        stat.mode,
        stat.uid,
        stat.gid,
        stat.size,
      ];
      fields.forEach((value, field) => {
        index.writeUInt32BE(low32(value), offset + (field * 4));
      });
      found = true;
    }
    const nameLength = encodedLength === 0x0fff
      ? nul - (offset + 62)
      : encodedLength;
    offset += (62 + nameLength + 1 + 7) & ~7;
  }
  assert.equal(found, true, `index must contain ${relative}`);
  createHash("sha1").update(index.subarray(0, -20)).digest().copy(index, index.length - 20);
  fs.writeFileSync(indexPath, index);
}

test("portable/operator manifest assigns every root test exactly once", () => {
  const manifest = loadAndAssertPortableRootTestManifest();
  const manifestLoader = fs.readFileSync(
    path.join(ROOT, "scripts", "test-harness", "portable-root-test-manifest.mjs"),
    "utf8",
  );
  assert.equal(manifest.portable_truth_status, PORTABLE_ROOT_TEST_TRUTH);
  assert.equal(manifest.operator_host_truth_status, OPERATOR_HOST_TEST_TRUTH);
  assert.equal(manifest.operator_host_file_count, 23);
  assert.deepEqual({
    discovered_file_count: manifest.discovered_file_count,
    discovered_files_sha256: manifest.discovered_files_sha256,
    operator_host_file_count: manifest.operator_host_file_count,
    operator_host_files_sha256: manifest.operator_host_files_sha256,
    portable_file_count: manifest.portable_file_count,
    portable_files_sha256: manifest.portable_files_sha256,
  }, {
    discovered_file_count: 91,
    discovered_files_sha256:
      "sha256:bc00ca3c111ae796193db7655e788fbc92b2cb7789cbedaab1f303f86431f90a",
    operator_host_file_count: 23,
    operator_host_files_sha256:
      "sha256:e37cb82d691324b183ce972a413f4251783bc032f28b9efb7b8ca7d9de5a6095",
    portable_file_count: 68,
    portable_files_sha256:
      "sha256:ac760a08c2fc62017fa918767ad24465c86e2b0565e184422625015f1fe65f9f",
  });
  assert.equal(
    createHash("sha256").update(fs.readFileSync(MANIFEST_PATH)).digest("hex"),
    "0e6981dd815c7445c8940a988cdd1602541bd457a6cb905e088e6e973b76853a",
  );
  assert.equal(manifest.portable.includes("scripts/portable-ci-test-split.test.mjs"), true);
  assert.equal(
    manifest.operator_host.includes("scripts/phala-pre-provision-authority-producer.test.mjs"),
    true,
  );
  assert.equal(
    manifest.operator_host.includes("scripts/release-authority-signature-verifier.test.mjs"),
    true,
  );
  assert.equal(
    manifest.operator_host.includes("scripts/phala-seven-cvm-verifier-evidence.test.mjs"),
    true,
  );
  assert.match(
    manifestLoader,
    /root test directory must be one canonical real directory[\s\S]*metadata\.nlink !== 1[\s\S]*fs\.realpathSync\(absolute\) !== absolute/,
  );
  assert.match(
    manifestLoader,
    /stat\.nlink !== 1[\s\S]*fs\.realpathSync\(MANIFEST_PATH\) !== MANIFEST_PATH/,
  );
});

test("portable runner rejects hooks, authority sentinels, credentials, and entrypoint selection", () => {
  for (const [result, pattern] of [
    [runnerFailure({ args: ["scripts/activation-preflight.test.mjs"] }), /caller-selected/],
    [runnerFailure({ execArgv: ["--trace-warnings"] }), /ordinary Node/],
    [
      runnerFailure({ environment: { DNAI_PORTABLE_CI_AUTHORITY: "forged" } }),
      /authority or credential environment/,
    ],
    [
      runnerFailure({ environment: { PHALA_CLOUD_API_KEY: "not-a-real-key" } }),
      /authority or credential environment/,
    ],
    [
      runnerFailure({ environment: { CF_PAGES_UPLOAD_JWT: "not-a-real-jwt" } }),
      /authority or credential environment/,
    ],
    [
      runnerFailure({ environment: { NODE_AUTH_TOKEN: "not-a-real-token" } }),
      /authority or credential environment/,
    ],
  ]) {
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, pattern);
  }
  for (const name of [
    "NODE_PATH",
    "NODE_USE_ENV_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SSLKEYLOGFILE",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
  ]) {
    const result = runnerFailure({ environment: { [name]: "injected" } });
    assert.notEqual(result.status, 0, name);
    const output = `${result.stdout}\n${result.stderr}`;
    if (!/authority or credential environment/.test(output)) {
      assert.match(name, /^(?:LD_PRELOAD|DYLD_INSERT_LIBRARIES)$/);
      assert.match(output, /(?:dylib|inserted|ld\.so|preload|shared object)/i);
    }
  }
  const selfErasingPreload = portableWrapperFailure({
    NODE_OPTIONS: "--import=data:text/javascript,delete%20process.env.NODE_OPTIONS",
  });
  assert.equal(selfErasingPreload.status, 64);
  assert.match(
    `${selfErasingPreload.stdout}\n${selfErasingPreload.stderr}`,
    /reject observable .*Node, TLS, and native-loader hooks/,
  );
  const webSelfErasingPreload = webWrapperFailure({
    NODE_OPTIONS: "--import=data:text/javascript,delete%20process.env.NODE_OPTIONS",
  });
  assert.equal(webSelfErasingPreload.status, 64);
  assert.match(
    `${webSelfErasingPreload.stdout}\n${webSelfErasingPreload.stderr}`,
    /reject observable .*Node, TLS, and native-loader hooks/,
  );
  const webCredential = webWrapperFailure({
    PHALA_CLOUD_API_KEY: "not-a-real-key",
  });
  assert.equal(webCredential.status, 65);
  assert.match(
    `${webCredential.stdout}\n${webCredential.stderr}`,
    /web portable CI rejects authority or credential environment: PHALA_CLOUD_API_KEY/,
  );
  assert.doesNotMatch(
    `${webCredential.stdout}\n${webCredential.stderr}`,
    /Generic-Linux portable web|npm (?:ci|run)/,
  );
  const portableCredential = portableWrapperFailure({
    PHALA_CLOUD_API_KEY: "not-a-real-key",
  });
  assert.equal(portableCredential.status, 65);
  assert.match(
    `${portableCredential.stdout}\n${portableCredential.stderr}`,
    /portable root CI rejects authority or credential environment: PHALA_CLOUD_API_KEY/,
  );
  assert.doesNotMatch(
    `${portableCredential.stdout}\n${portableCredential.stderr}`,
    /truth: portable_test_suites|generic-ci-npm-runtime-authority/,
  );
  const operatorCredential = operatorWrapperFailure({
    PHALA_CLOUD_API_KEY: "not-a-real-key",
  });
  assert.equal(operatorCredential.status, 65);
  assert.match(
    `${operatorCredential.stdout}\n${operatorCredential.stderr}`,
    /operator-host tests rejects authority or credential environment: PHALA_CLOUD_API_KEY/,
  );
  assert.doesNotMatch(
    `${operatorCredential.stdout}\n${operatorCredential.stderr}`,
    /Full root and web Node gates|truth:/,
  );
  const secretCredential = secretWrapperFailure({
    PHALA_CLOUD_API_KEY: "not-a-real-key",
  });
  assert.equal(secretCredential.status, 65);
  assert.match(
    `${secretCredential.stdout}\n${secretCredential.stderr}`,
    /secret scan rejects authority or credential environment: PHALA_CLOUD_API_KEY/,
  );
  assert.doesNotMatch(secretCredential.stdout, /Secret scan passed/);
  const foundrySelector = foundryWrapperFailure({
    FOUNDRY_MATCH_TEST: "__dnai_no_test_can_match_this__",
  });
  assert.equal(foundrySelector.status, 65);
  assert.match(
    `${foundrySelector.stdout}\n${foundrySelector.stderr}`,
    /rejects caller-controlled Foundry configuration: FOUNDRY_MATCH_TEST/,
  );
  assert.doesNotMatch(
    `${foundrySelector.stdout}\n${foundrySelector.stderr}`,
    /Foundry contracts|truth:/,
  );
  const startupRoot = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-shell-hook-kat-"));
  try {
    const selfErasingBashEnv = path.join(startupRoot, "self-erasing-bash-env.sh");
    fs.writeFileSync(selfErasingBashEnv, [
      "node() { return 0; }",
      "npm() { return 0; }",
      "unset BASH_ENV",
      "",
    ].join("\n"), { mode: 0o600 });
    const hashedNodeBashEnv = path.join(startupRoot, "hashed-node-bash-env.sh");
    fs.writeFileSync(hashedNodeBashEnv, [
      "hash -p /usr/bin/true node",
      "unset BASH_ENV",
      "",
    ].join("\n"), { mode: 0o600 });
    const fakeBin = path.join(startupRoot, "fake-bin");
    fs.mkdirSync(fakeBin, { mode: 0o700 });
    fs.symlinkSync("/usr/bin/true", path.join(fakeBin, "node"));
    fs.symlinkSync("/usr/bin/true", path.join(fakeBin, "npm"));
    const fakeRegularBin = path.join(startupRoot, "fake-regular-bin");
    fs.mkdirSync(fakeRegularBin, { mode: 0o700 });
    fs.copyFileSync("/usr/bin/true", path.join(fakeRegularBin, "node"));
    fs.copyFileSync("/usr/bin/true", path.join(fakeRegularBin, "npm"));
    fs.chmodSync(path.join(fakeRegularBin, "node"), 0o755);
    fs.chmodSync(path.join(fakeRegularBin, "npm"), 0o755);
    const wrapperAliasRoot = path.join(startupRoot, "wrapper-alias-root");
    const wrapperAliasScripts = path.join(wrapperAliasRoot, "scripts");
    fs.mkdirSync(wrapperAliasScripts, { recursive: true, mode: 0o700 });
    fs.symlinkSync(
      path.join(ROOT, "scripts", "verify-local.sh"),
      path.join(wrapperAliasScripts, "verify-local.sh"),
    );
    fs.writeFileSync(
      path.join(wrapperAliasScripts, "ci-secret-scan.sh"),
      "#!/bin/sh\nprintf '%s\\n' attacker-root-executed\n",
      { mode: 0o700 },
    );
    const wrapperAlias = spawnSync(
      path.join(wrapperAliasScripts, "verify-local.sh"),
      ["secrets"],
      {
        cwd: wrapperAliasRoot,
        encoding: "utf8",
        env: { ...process.env },
        maxBuffer: 64 * 1024,
        timeout: 15_000,
      },
    );
    assert.equal(wrapperAlias.status, 64);
    assert.match(
      `${wrapperAlias.stdout}\n${wrapperAlias.stderr}`,
      /must not be invoked through a symlink/,
    );
    assert.doesNotMatch(
      `${wrapperAlias.stdout}\n${wrapperAlias.stderr}`,
      /attacker-root-executed/,
    );
    const wrapperHardlinkRoot = path.join(startupRoot, "wrapper-hardlink-root");
    const wrapperHardlinkScripts = path.join(wrapperHardlinkRoot, "scripts");
    fs.mkdirSync(wrapperHardlinkScripts, { recursive: true, mode: 0o700 });
    fs.linkSync(
      path.join(ROOT, "scripts", "verify-local.sh"),
      path.join(wrapperHardlinkScripts, "verify-local.sh"),
    );
    fs.writeFileSync(
      path.join(wrapperHardlinkScripts, "ci-secret-scan.sh"),
      "#!/bin/sh\nprintf '%s\\n' attacker-hardlink-root-executed\n",
      { mode: 0o700 },
    );
    const wrapperHardlink = spawnSync(
      path.join(wrapperHardlinkScripts, "verify-local.sh"),
      ["secrets"],
      {
        cwd: wrapperHardlinkRoot,
        encoding: "utf8",
        env: { ...process.env },
        maxBuffer: 64 * 1024,
        timeout: 15_000,
      },
    );
    assert.equal(wrapperHardlink.status, 64);
    assert.match(
      `${wrapperHardlink.stdout}\n${wrapperHardlink.stderr}`,
      /not one canonical protected regular file|path is not the canonical repository entrypoint/,
    );
    assert.doesNotMatch(
      `${wrapperHardlink.stdout}\n${wrapperHardlink.stderr}`,
      /attacker-hardlink-root-executed/,
    );
    fs.unlinkSync(path.join(wrapperHardlinkScripts, "verify-local.sh"));
    for (const result of [
      portableWrapperFailure({ BASH_ENV: selfErasingBashEnv }),
      webWrapperFailure({ BASH_ENV: selfErasingBashEnv }),
      portableWrapperFailure({ BASH_ENV: hashedNodeBashEnv }),
      webWrapperFailure({ NPM_CONFIG_SCRIPT_SHELL: "/usr/bin/true" }),
      webWrapperFailure({
        npm_config_node_options:
          "--import=data:text/javascript,process.exit(0)",
      }),
      webWrapperFailure({ NPM_CONFIG_USERCONFIG: "/tmp/attacker-npmrc" }),
      portableWrapperFailure({ PERL5OPT: "-MUntrustedDigestHook" }),
      webWrapperFailure({ PERL5LIB: "/tmp/untrusted-perl-library" }),
    ]) {
      assert.equal(result.status, 64);
      assert.match(
        `${result.stdout}\n${result.stderr}`,
        /reject observable shell, interpreter, Node, TLS, and native-loader hooks/,
      );
      assert.doesNotMatch(
        `${result.stdout}\n${result.stderr}`,
        /Generic-Linux portable web|truth: portable_test_suites|npm (?:ci|run)/,
      );
    }
    const importedFunction = portableWrapperFailure({
      "BASH_FUNC_node%%": "() { return 0; }",
    });
    assert.equal(importedFunction.status, 64);
    // Linux Bash privileged mode strips the exported function before line 1,
    // so the next exact-HEAD launch guard is the first observable rejection.
    // Darwin leaves the hostile variable observable to the startup-hook guard.
    assert.match(
      `${importedFunction.stdout}\n${importedFunction.stderr}`,
      process.platform === "linux"
        ? /reject observable shell, interpreter, Node, TLS, and native-loader hooks|wrapper materialized from the exact HEAD blob/
        : /reject observable shell, interpreter, Node, TLS, and native-loader hooks/,
    );
    assert.doesNotMatch(
      `${importedFunction.stdout}\n${importedFunction.stderr}`,
      /Generic-Linux portable web|truth: portable_test_suites|npm (?:ci|run)/,
    );
    const xtraceSecret = "must-not-appear-in-shell-trace";
    const xtrace = webWrapperFailure({
      SHELLOPTS: "xtrace",
      PS4: xtraceSecret,
      PHALA_CLOUD_API_KEY: xtraceSecret,
    });
    assert.equal(xtrace.status, 64);
    assert.doesNotMatch(`${xtrace.stdout}\n${xtrace.stderr}`, new RegExp(xtraceSecret));
    const observableLoader = portableWrapperFailure({
      LD_LIBRARY_PATH: "/tmp/untrusted-native-libraries",
    });
    assert.equal(observableLoader.status, 64);
    assert.match(
      `${observableLoader.stdout}\n${observableLoader.stderr}`,
      /reject observable .*native-loader hook/,
    );
    assert.doesNotMatch(
      `${observableLoader.stdout}\n${observableLoader.stderr}`,
      /Generic-Linux portable web|truth:/,
    );
    for (const result of [
      portableWrapperFailure({ PATH: `${fakeBin}:/usr/bin:/bin` }),
      webWrapperFailure({ PATH: `${fakeBin}:/usr/bin:/bin` }),
      portableWrapperFailure({ PATH: `${fakeRegularBin}:/usr/bin:/bin` }),
      webWrapperFailure({ PATH: `${fakeRegularBin}:/usr/bin:/bin` }),
      spawnSync(path.join(ROOT, "scripts", "verify-local.sh"), ["operator-host"], {
        cwd: ROOT,
        encoding: "utf8",
        env: { ...process.env, PATH: `${fakeBin}:/usr/bin:/bin` },
        maxBuffer: 64 * 1024,
        timeout: 15_000,
      }),
      spawnSync(path.join(ROOT, "scripts", "verify-local.sh"), ["operator-host"], {
        cwd: ROOT,
        encoding: "utf8",
        env: { ...process.env, PATH: `${fakeRegularBin}:/usr/bin:/bin` },
        maxBuffer: 64 * 1024,
        timeout: 15_000,
      }),
    ]) {
      assert.equal(result.status, 64);
      assert.doesNotMatch(
        `${result.stdout}\n${result.stderr}`,
        /Full root Node gate|Generic-Linux portable web|truth:/,
      );
    }
    const hostileAmbient = webWrapperFailure({
      HOME: startupRoot,
      TMPDIR: startupRoot,
      CI: "false",
      LANG: "attacker_LOCALE",
      LC_ALL: "attacker_LOCALE",
    });
    assert.equal(hostileAmbient.status, 64);
    assert.doesNotMatch(
      `${hostileAmbient.stdout}\n${hostileAmbient.stderr}`,
      /Generic-Linux portable web|truth:/,
    );
  } finally {
    fs.rmSync(startupRoot, { force: true, recursive: true });
  }
  const credentialNames = [
    "QVL_AUTH_TOKEN",
    "METERING_AUTH_TOKEN",
    "NEKO_PASSWORD",
    "NEKO_PASSWORD_ADMIN",
    "ORACLE_RUNTIME_AUTH_TOKEN",
    "KMS_SIGNER_KEY_PATH",
    "JUDGE_SIGNER_KEY_PATH",
    "DEV_KEY",
    "JWT_SECRET",
    "PG_PASSWORD",
    "TINKER_ARENA_CANDIDATE_INGRESS_LOCAL_KEY_FILE",
    "TINKER_ARENA_CANDIDATE_INGRESS_PRIVATE_KEY_HEX",
    "TINKER_ARENA_PROVISION_AUTH_KEY_B64",
    "TINKER_ARENA_PROVISION_EVALUATOR_B64",
    "TINKER_ARENA_AGENT_STORE_INTEGRITY_KEY",
    "TINKER_COMPUTE_CREDENTIAL_SIGNING_KEY",
    "TINKER_WALLET_AUTH_RPC_URL_SECONDARY",
    "QVL_RELEASE_POLICY_B64",
    "TELEGRAM_BOT_TOKEN",
    "TINKER_ARENA_PROVISION_AUTH_TAG",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "CF_API_KEY",
    "CF_API_TOKEN",
    "CF_PAGES_UPLOAD_JWT",
    "CLOUDFLARE_API_KEY",
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_EMAIL",
    "NODE_AUTH_TOKEN",
    "NPM_TOKEN",
    "TINKER_BASE_URL",
  ];
  assert.deepEqual(
    forbiddenPortableProfileEnvironmentNames(
      Object.fromEntries(credentialNames.map((name) => [name, "injected"])),
    ),
    [...credentialNames].sort(),
  );
  const aliasRoot = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-portable-profile-alias-"));
  try {
    const alias = path.join(aliasRoot, "portable-profile.mjs");
    fs.symlinkSync(
      path.join(ROOT, "scripts", "test-harness", "portable-root-test-profile.mjs"),
      alias,
    );
    const aliased = spawnSync(process.execPath, [alias], {
      cwd: ROOT,
      encoding: "utf8",
      env: { ...process.env, PHALA_CLOUD_API_KEY: "injected" },
      maxBuffer: 64 * 1024,
      timeout: 15_000,
    });
    assert.notEqual(aliased.status, 0);
    assert.match(`${aliased.stdout}\n${aliased.stderr}`, /authority or credential environment/);
  } finally {
    fs.rmSync(aliasRoot, { force: true, recursive: true });
  }
});

test("clean release workspace guard accepts ordinary clones and rejects hidden Git execution/state", () => {
  const fixture = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-clean-workspace-kat-"),
  ));
  const gitEnvironment = {
    GIT_AUTHOR_EMAIL: "kat@example.invalid",
    GIT_AUTHOR_NAME: "Release KAT",
    GIT_COMMITTER_EMAIL: "kat@example.invalid",
    GIT_COMMITTER_NAME: "Release KAT",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    HOME: fixture,
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
  };
  const git = (...args) => spawnSync("/usr/bin/git", ["-C", fixture, ...args], {
    cwd: fixture,
    encoding: "utf8",
    env: gitEnvironment,
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
  try {
    assert.equal(git("init", "--quiet").status, 0);
    assert.equal(git("config", "extensions.worktreeConfig", "true").status, 0);
    assert.equal(fs.existsSync(path.join(fixture, ".git", "config.worktree")), false);
    assert.equal(git("config", "index.version", "2").status, 0);
    const fixtureHelper = path.join(
      fixture,
      "scripts",
      "test-harness",
      "exact-head-worktree-authority.mjs",
    );
    fs.mkdirSync(path.dirname(fixtureHelper), { recursive: true, mode: 0o755 });
    fs.copyFileSync(
      path.join(
        ROOT,
        "scripts",
        "test-harness",
        "exact-head-worktree-authority.mjs",
      ),
      fixtureHelper,
    );
    fs.chmodSync(fixtureHelper, 0o644);
    fs.writeFileSync(path.join(fixture, "tracked.txt"), "reviewed\n", { mode: 0o644 });
    assert.equal(git("add", "--", ".").status, 0);
    assert.equal(git("-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "KAT").status, 0);
    assert.equal(git("checkout", "--quiet", "--detach").status, 0);
    const clean = runExtractedCleanWorkspaceGuard(fixture);
    assert.equal(clean.status, 0, `${clean.stdout}\n${clean.stderr}`);

    const marker = path.join(fixture, ".git", "fsmonitor-executed");
    const monitor = path.join(fixture, ".git", "hostile-fsmonitor.sh");
    fs.writeFileSync(
      monitor,
      `#!/bin/sh\n: > ${JSON.stringify(marker)}\nexit 0\n`,
      { mode: 0o755 },
    );
    assert.equal(git("config", "--local", "core.fsmonitor", monitor).status, 0);
    const fsmonitor = runExtractedCleanWorkspaceGuard(fixture);
    assert.equal(fsmonitor.status, 65);
    assert.match(`${fsmonitor.stdout}\n${fsmonitor.stderr}`, /unsafe local Git configuration/);
    assert.equal(fs.existsSync(marker), false);
    assert.equal(git("config", "--local", "--unset-all", "core.fsmonitor").status, 0);

    assert.equal(git("update-index", "--assume-unchanged", "tracked.txt").status, 0);
    fs.writeFileSync(path.join(fixture, "tracked.txt"), "tampered\n", { mode: 0o644 });
    const hiddenIndex = runExtractedCleanWorkspaceGuard(fixture);
    assert.equal(hiddenIndex.status, 65);
    assert.match(
      `${hiddenIndex.stdout}\n${hiddenIndex.stderr}`,
      /hidden or nonordinary Git index state|worktree bytes do not match immutable HEAD/,
    );
    assert.equal(git("update-index", "--no-assume-unchanged", "tracked.txt").status, 0);
    fs.writeFileSync(path.join(fixture, "tracked.txt"), "reviewed\n", { mode: 0o644 });
    assert.equal(git("add", "--", "tracked.txt").status, 0);

    const filterMarker = path.join(fixture, ".git", "clean-filter-executed");
    const filterProgram = path.join(fixture, ".git", "hostile-clean-filter.sh");
    fs.mkdirSync(path.join(fixture, ".git", "info"), { recursive: true });
    fs.writeFileSync(
      path.join(fixture, ".git", "info", "attributes"),
      "tracked.txt filter=evil\n",
    );
    fs.writeFileSync(
      filterProgram,
      `#!/bin/sh\n: > ${JSON.stringify(filterMarker)}\ncat\n`,
      { mode: 0o755 },
    );
    assert.equal(git("config", "--local", "filter.evil.clean", filterProgram).status, 0);
    assert.equal(git("config", "--local", "filter.evil.required", "true").status, 0);
    const cleanFilter = runExtractedCleanWorkspaceGuard(fixture);
    assert.equal(cleanFilter.status, 65);
    assert.match(`${cleanFilter.stdout}\n${cleanFilter.stderr}`, /unsafe local Git configuration/);
    assert.equal(fs.existsSync(filterMarker), false, "clean filter must not execute");
    assert.equal(git("config", "--local", "--remove-section", "filter.evil").status, 0);
    fs.rmSync(path.join(fixture, ".git", "info", "attributes"), { force: true });

    const tracked = path.join(fixture, "tracked.txt");
    fs.writeFileSync(tracked, "tampered\n", { mode: 0o644 });
    fs.utimesSync(tracked, new Date(946684800000), new Date(946684800000));
    forgeOrdinaryIndexStatCache({
      file: tracked,
      gitDirectory: path.join(fixture, ".git"),
      relative: "tracked.txt",
    });
    const forgedStatus = git("status", "--porcelain=v1", "--untracked-files=all");
    assert.equal(forgedStatus.status, 0);
    assert.equal(forgedStatus.stdout, "", "forged ordinary index must fool porcelain");
    const forgedPrefix = git("ls-files", "-v", "--", "tracked.txt");
    assert.equal(forgedPrefix.status, 0);
    assert.match(forgedPrefix.stdout, /^H tracked\.txt\n$/);
    const forgedIndex = runExtractedCleanWorkspaceGuard(fixture);
    assert.equal(forgedIndex.status, 65);
    assert.match(
      `${forgedIndex.stdout}\n${forgedIndex.stderr}`,
      /worktree bytes do not match immutable HEAD|tracked file bytes or metadata do not match HEAD/,
    );

    fs.writeFileSync(tracked, "reviewed\n", { mode: 0o644 });
    assert.equal(git("add", "--", "tracked.txt").status, 0);
    const newlineCredential = path.join(fixture, ".env.\nproduction");
    fs.writeFileSync(newlineCredential, "not-a-real-secret\n", { mode: 0o644 });
    assert.equal(git("add", "--", newlineCredential).status, 0);
    assert.equal(
      git("-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "path KAT").status,
      0,
    );
    const newlinePath = runExtractedCleanWorkspaceGuard(fixture);
    assert.equal(newlinePath.status, 65);
    assert.match(
      `${newlinePath.stdout}\n${newlinePath.stderr}`,
      /canonical repository-relative path|worktree bytes do not match immutable HEAD/,
    );
    assert.equal(git("rm", "--quiet", "--", newlineCredential).status, 0);
    assert.equal(
      git("-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "remove path KAT").status,
      0,
    );
    const gitlinkOid = git("rev-parse", "--verify", "HEAD").stdout.trim();
    assert.match(gitlinkOid, /^[0-9a-f]{40}$/);
    assert.equal(
      git("update-index", "--add", "--cacheinfo", `160000,${gitlinkOid},nested-submodule`).status,
      0,
    );
    assert.equal(
      git("-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "gitlink KAT").status,
      0,
    );
    fs.mkdirSync(path.join(fixture, "nested-submodule"), { mode: 0o755 });
    const emptyGitlink = runExtractedCleanWorkspaceGuard(fixture);
    assert.equal(emptyGitlink.status, 0, `${emptyGitlink.stdout}\n${emptyGitlink.stderr}`);
    fs.writeFileSync(path.join(fixture, "nested-submodule", "unreviewed.txt"), "unreviewed\n");
    const initializedGitlink = runExtractedCleanWorkspaceGuard(fixture);
    assert.equal(initializedGitlink.status, 65);
    assert.match(
      `${initializedGitlink.stdout}\n${initializedGitlink.stderr}`,
      /gitlink boundary must remain uninitialized and empty/,
    );
  } finally {
    fs.rmSync(fixture, { force: true, recursive: true });
  }
});

test("HEAD-materialized wrapper is the bootstrap authority, not mutable worktree bytes", () => {
  const fixture = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-head-wrapper-kat-"),
  ));
  const materializedRoot = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-materialized-wrapper-kat-"),
  ));
  const gitEnvironment = {
    GIT_AUTHOR_EMAIL: "kat@example.invalid",
    GIT_AUTHOR_NAME: "Release KAT",
    GIT_COMMITTER_EMAIL: "kat@example.invalid",
    GIT_COMMITTER_NAME: "Release KAT",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    HOME: fixture,
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
  };
  const git = (...args) => spawnSync("/usr/bin/git", ["-C", fixture, ...args], {
    cwd: fixture,
    encoding: "utf8",
    env: gitEnvironment,
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
  try {
    assert.equal(git("init", "--quiet").status, 0);
    assert.equal(git("config", "extensions.worktreeConfig", "true").status, 0);
    assert.equal(fs.existsSync(path.join(fixture, ".git", "config.worktree")), false);
    const fixtureScripts = path.join(fixture, "scripts");
    fs.mkdirSync(fixtureScripts, { mode: 0o755 });
    const fixtureHarness = path.join(fixtureScripts, "test-harness");
    fs.mkdirSync(fixtureHarness, { mode: 0o755 });
    const fixtureWrapper = path.join(fixtureScripts, "verify-local.sh");
    const fixtureProjector = path.join(
      fixtureHarness,
      "exact-head-worktree-authority.mjs",
    );
    const fixtureScanner = path.join(fixtureScripts, "ci-secret-scan.sh");
    fs.copyFileSync(path.join(ROOT, "scripts", "verify-local.sh"), fixtureWrapper);
    fs.chmodSync(fixtureWrapper, 0o755);
    fs.copyFileSync(
      path.join(ROOT, "scripts", "test-harness", "exact-head-worktree-authority.mjs"),
      fixtureProjector,
    );
    fs.chmodSync(fixtureProjector, 0o644);
    fs.writeFileSync(
      fixtureScanner,
      "#!/bin/sh\nprintf '%s\\n' exact-head-secret-scan\n",
      { mode: 0o755 },
    );
    assert.equal(git("add", "--", "scripts").status, 0);
    assert.equal(
      git("-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "wrapper KAT").status,
      0,
    );
    const head = git("rev-parse", "--verify", "HEAD").stdout.trim();
    assert.match(head, /^[0-9a-f]{40}$/);
    const materialized = path.join(materializedRoot, "verify-local.sh");
    fs.copyFileSync(fixtureWrapper, materialized);
    fs.chmodSync(materialized, 0o755);
    fs.writeFileSync(fixtureWrapper, "#!/bin/sh\nprintf '%s\\n' attacker-worktree-wrapper\n");
    fs.chmodSync(fixtureWrapper, 0o755);
    fs.writeFileSync(
      fixtureScanner,
      "#!/bin/sh\nprintf '%s\\n' attacker-worktree-secret-scan\nexit 0\n",
    );
    fs.chmodSync(fixtureScanner, 0o755);
    const environment = {
      HOME: fixture,
      LANG: "C",
      LC_ALL: "C",
      PATH: process.env.PATH || "/usr/bin:/bin",
    };
    const exactHead = spawnSync("/bin/bash", [
      "-p",
      materialized,
      "--head-materialized-root",
      fixture,
      head,
      "secrets",
    ], {
      cwd: fixture,
      encoding: "utf8",
      env: environment,
      maxBuffer: 64 * 1024,
      timeout: 15_000,
    });
    assert.equal(exactHead.status, 0, `${exactHead.stdout}\n${exactHead.stderr}`);
    assert.match(exactHead.stdout, /^exact-head-secret-scan\n$/);
    assert.doesNotMatch(
      exactHead.stdout,
      /attacker-worktree-(?:wrapper|secret-scan)/,
    );

    fs.appendFileSync(materialized, "\n# tampered materialized bytes\n");
    const tampered = spawnSync("/bin/bash", [
      "-p",
      materialized,
      "--head-materialized-root",
      fixture,
      head,
      "secrets",
    ], {
      cwd: fixture,
      encoding: "utf8",
      env: environment,
      maxBuffer: 64 * 1024,
      timeout: 15_000,
    });
    assert.equal(tampered.status, 64);
    assert.match(
      `${tampered.stdout}\n${tampered.stderr}`,
      /wrapper bytes do not match the exact source commit/,
    );
    assert.doesNotMatch(tampered.stdout, /exact-head-secret-scan/);
  } finally {
    fs.rmSync(fixture, { force: true, recursive: true });
    fs.rmSync(materializedRoot, { force: true, recursive: true });
  }
});

test("CI keeps portable tests, operator rejection, frontend build, and local full gates distinct", () => {
  const workflow = fs.readFileSync(path.join(ROOT, ".github", "workflows", "ci.yml"), "utf8");
  assert.equal((workflow.match(/version: v1\.5\.1/g) || []).length, 2);
  assert.doesNotMatch(workflow, /version: stable/);
  assert.equal((workflow.match(/node-version: 22\.23\.2/g) || []).length, 4);
  assert.doesNotMatch(workflow, /node-version:\s*22\s*(?:#.*)?$/m);
  const canonicalNodeSteps = [...workflow.matchAll(
    /^      - name: Canonicalize pinned Node release authority\n[\s\S]*?(?=^      - (?:name|uses):)/gm,
  )].map((match) => match[0]);
  assert.equal(canonicalNodeSteps.length, 4);
  assert.equal(new Set(canonicalNodeSteps).size, 1);
  const canonicalNodeStep = canonicalNodeSteps[0];
  assert.match(
    canonicalNodeStep,
    /env:\n\s+LD_PRELOAD: ""\n\s+LD_AUDIT: ""\n\s+LD_LIBRARY_PATH: ""\n\s+DYLD_INSERT_LIBRARIES: ""\n\s+DYLD_LIBRARY_PATH: ""/,
  );
  assert.match(canonicalNodeStep, /source_node="\$\(type -P node\)"/);
  assert.match(canonicalNodeStep, /\/usr\/bin\/readlink -f -- "\$source_node"/);
  assert.match(
    canonicalNodeStep,
    /3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327/,
  );
  assert.match(canonicalNodeStep, /-e "\$runtime_root" \|\| -L "\$runtime_root"/);
  assert.match(canonicalNodeStep, /\/bin\/mkdir -m 0700 -- "\$runtime_root"/);
  assert.match(canonicalNodeStep, /\/usr\/bin\/install -d -m 0755 --/);
  assert.match(canonicalNodeStep, /\/usr\/bin\/install -m 0755 -- "\$source_node"/);
  assert.match(canonicalNodeStep, /\/bin\/cp -a --no-preserve=ownership --/);
  assert.match(
    canonicalNodeStep,
    /\/bin\/ln -s \.\.\/lib\/node_modules\/npm\/bin\/npm-cli\.js "\$runtime_root\/bin\/npm"/,
  );
  assert.match(
    canonicalNodeStep,
    /\/usr\/bin\/printf '%s\\n' "\$runtime_root\/bin" >> "\$GITHUB_PATH"/,
  );
  assert.doesNotMatch(canonicalNodeStep, /chmod[\s\S]*node_modules\/npm/);
  assert.equal(
    (workflow.match(
      /node-version: 22\.23\.2(?:\n          (?:cache|cache-dependency-path): [^\n]+)*\n      - name: Canonicalize pinned Node release authority/g,
    ) || []).length,
    4,
  );
  assert.equal(
    (workflow.match(/name: Canonicalize pinned Node release authority/g) || []).length,
    4,
  );
  assert.equal(
    (workflow.match(/3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327/g) || []).length,
    4,
  );
  assert.equal(
    (workflow.match(/\/bin\/cp -a --no-preserve=ownership --/g) || []).length,
    4,
  );
  assert.equal(
    (workflow.match(/>> "\$GITHUB_PATH"/g) || []).length,
    4,
  );
  assert.equal((workflow.match(/uses: actions\/checkout@/g) || []).length, 4);
  assert.equal((workflow.match(/persist-credentials: false/g) || []).length, 4);
  assert.match(
    workflow,
    /Generic Linux proves portable source logic only[\s\S]*cannot satisfy the[\s\S]*frozen Darwin operator authorities[\s\S]*exact-HEAD materialized wrapper[\s\S]*mutable worktree script is not bootstrap authority/,
  );
  assert.doesNotMatch(workflow, /register-portable-authority-loader|DNAI_PORTABLE_CI_AUTHORITY/);
  const removedLoaderPaths = [
    "scripts/portable-ci-authority-harness.test.mjs",
    "scripts/test-harness/portable-authority-loader-hooks.mjs",
    "scripts/test-harness/portable-codesign-fixture.sh",
    "scripts/test-harness/portable-dcap-runtime-fixture.mjs",
    "scripts/test-harness/portable-phala-seven-cvm-opened-fd-runtime-test-harness.mjs",
    "scripts/test-harness/portable-release-authority-signature-verifier.mjs",
    "scripts/test-harness/register-portable-authority-loader.mjs",
  ];
  for (const removedPath of removedLoaderPaths) {
    assert.equal(fs.existsSync(path.join(ROOT, removedPath)), false, removedPath);
    assert.equal(workflow.includes(path.basename(removedPath)), false, removedPath);
  }
  assert.doesNotMatch(
    workflow,
    /explicit_hermetic_fixture_authority_not_operator_host_activation|--import|--loader/,
  );
  const rejectionProbe = fs.readFileSync(
    path.join(ROOT, "scripts", "test-harness", "operator-authority-fail-closed-probe.mjs"),
    "utf8",
  );
  assert.match(rejectionProbe, /version: "1\.5\.1-v1\.5\.1"/);
  assert.match(rejectionProbe, /commit_sha: "b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2"/);
  assert.match(rejectionProbe, /build_profile: "maxperf"/);
  assert.match(rejectionProbe, /assertPinnedCastSignatureVerifier\(\)/);
  assert.match(rejectionProbe, /DNAI_GENERIC_CI_CAST_PATH/);
  assert.match(
    rejectionProbe,
    /7b25a9c61dac49a0718ba3c2d37ba638014f3baf35739777b2d809780914e91d/,
  );
  assert.match(rejectionProbe, /bytes do not match the reviewed SHA-256/);
  assert.doesNotMatch(
    rejectionProbe,
    /PINNED_CAST_SIGNATURE_VERIFIER\.version|PINNED_CAST_SIGNATURE_VERIFIER\.commit_sha|PINNED_CAST_SIGNATURE_VERIFIER\.build_profile/,
  );
  const webBlock = workflow.match(/\n  web:[\s\S]*$/)?.[0] || "";
  const castStep = webBlock.indexOf(
    "Canonicalize generic Linux cast for rejection evidence",
  );
  const webCiStep = webBlock.indexOf(
    "Verify generic-Linux portable web and root gates — not operator-host activation authority",
  );
  assert.ok(castStep > 0 && webCiStep > castStep);
  assert.equal((workflow.match(/--head-materialized-root/g) || []).length, 4);
  assert.equal((workflow.match(/GIT_NO_REPLACE_OBJECTS=1 GIT_PAGER=cat/g) || []).length, 4);
  assert.equal((workflow.match(/show \\\n\s+"\$GITHUB_SHA:scripts\/verify-local\.sh"/g) || []).length, 4);
  const reviewedShell = "shell: /bin/bash --noprofile --norc -p -e -o pipefail {0}";
  assert.equal(
    (workflow.match(
      /^\s*shell: \/bin\/bash --noprofile --norc -p -e -o pipefail \{0\}$/gm,
    ) || []).length,
    9,
  );
  assert.equal(
    (workflow.match(/^\s*shell:.*$/gm) || []).length,
    9,
  );
  assert.doesNotMatch(
    workflow,
    /shell: \/bin\/bash -p --noprofile --norc/,
  );
  assert.equal(workflow.includes(reviewedShell), true);
  assert.match(
    webBlock.slice(webCiStep),
    /--head-materialized-root \\\n\s+"\$GITHUB_WORKSPACE" "\$GITHUB_SHA" web-ci/,
  );
  assert.match(
    webBlock.slice(webCiStep),
    /env:\n\s+LD_PRELOAD: ""\n\s+LD_AUDIT: ""\n\s+LD_LIBRARY_PATH: ""\n\s+DYLD_INSERT_LIBRARIES: ""\n\s+DYLD_LIBRARY_PATH: ""/,
  );
  assert.doesNotMatch(
    webBlock,
    /working-directory: web|run: npm ci|npm run check|verify-local\.sh portable-ci/,
  );
  const contractsBlock = workflow.match(/\n  contracts:[\s\S]*?\n  python:/)?.[0] || "";
  assert.match(
    contractsBlock,
    /Build contracts with portable Node suites[\s\S]*env:\n\s+LD_PRELOAD: ""\n\s+LD_AUDIT: ""\n\s+LD_LIBRARY_PATH: ""\n\s+DYLD_INSERT_LIBRARIES: ""\n\s+DYLD_LIBRARY_PATH: ""[\s\S]*--head-materialized-root[\s\S]*"\$GITHUB_WORKSPACE" "\$GITHUB_SHA" foundry-ci/,
  );
  assert.doesNotMatch(contractsBlock, /working-directory: web|run: npm ci/);
  const pythonBlock = workflow.match(/\n  python:[\s\S]*?\n  web:/)?.[0] || "";
  assert.match(pythonBlock, /setup-node@[0-9a-f]+[\s\S]*node-version: 22\.23\.2/);
  assert.doesNotMatch(pythonBlock, /working-directory: web|run: npm ci/);
  assert.doesNotMatch(workflow, /node scripts\/test-harness\/run-portable-root-tests\.mjs/);
  const localGate = fs.readFileSync(path.join(ROOT, "scripts", "verify-local.sh"), "utf8");
  const genericNpmAuthority = fs.readFileSync(
    path.join(
      ROOT,
      "scripts",
      "test-harness",
      "generic-ci-npm-runtime-authority.mjs",
    ),
    "utf8",
  );
  const releaseRuntimeCore = fs.readFileSync(
    path.join(ROOT, "web", "scripts", "release-runtime-pins-core.mjs"),
  );
  const exactHeadWorktreeAuthority = fs.readFileSync(
    path.join(
      ROOT,
      "scripts",
      "test-harness",
      "exact-head-worktree-authority.mjs",
    ),
  );
  assert.match(localGate, /^#!\/bin\/bash -p\nset \+x\n/);
  assert.match(
    localGate.match(/assert_plain_shell_startup_environment\(\)[\s\S]*?\n}/)?.[0] || "",
    /BASH_ENV[\s\S]*BASH_FUNC_\*[\s\S]*NPM_CONFIG_\*[\s\S]*npm_config_\*[\s\S]*npm_execpath[\s\S]*INIT_CWD[\s\S]*PERL5OPT[\s\S]*PERL5LIB/,
  );
  assert.match(localGate, /assert_plain_shell_startup_environment\nhash -r/);
  assert.equal(
    createHash("sha256").update(exactHeadWorktreeAuthority).digest("hex"),
    "54c88fc8667310ad4b46f67488d8ee5926b6972c42d34fcad20dce199f2ec367",
  );
  assert.match(
    exactHeadWorktreeAuthority.toString("utf8"),
    /O_NOFOLLOW[\s\S]*blob \$\{entry\.size\}\\0/,
  );
  assert.match(exactHeadWorktreeAuthority.toString("utf8"), /ls-tree/);
  assert.match(exactHeadWorktreeAuthority.toString("utf8"), /ls-files[\s\S]*--stage/);
  assert.match(
    exactHeadWorktreeAuthority.toString("utf8"),
    /120000|160000/,
  );
  assert.match(
    exactHeadWorktreeAuthority.toString("utf8"),
    /gitlink boundary must remain uninitialized and empty[\s\S]*assertNoUnexpectedWorktreeEntries/,
  );
  assert.match(
    localGate.match(/assert_exact_head_worktree_authority\(\)[\s\S]*?\n}/)?.[0] || "",
    /54c88fc8667310ad4b46f67488d8ee5926b6972c42d34fcad20dce199f2ec367[\s\S]*AUTHENTICATED_GATE_NODE_EXECUTABLE[\s\S]*extra_profile[\s\S]*LAST_EXACT_HEAD_WORKTREE_HEAD/,
  );
  assert.match(
    localGate,
    /NAMED_SCRIPT_PATH="\$\{BASH_SOURCE\[0\]\}"[\s\S]*--head-materialized-root[\s\S]*-L "\$NAMED_SCRIPT_PATH"[\s\S]*\/bin\/realpath[\s\S]*SCRIPT_METADATA[\s\S]*1:\$\{SCRIPT_EXPECTED_UID}:755[\s\S]*GIT_NO_REPLACE_OBJECTS=1[\s\S]*hash-object --no-filters[\s\S]*wrapper bytes do not match the exact source commit[\s\S]*CANONICAL_SCRIPT_PATH%\/scripts\/verify-local\.sh/,
  );
  assert.match(
    localGate,
    /caller checkout is only an object source[\s\S]*remote\.\*\.promisor[\s\S]*extensions\.partialclone[\s\S]*objects\/info\/alternates[\s\S]*clone --no-local --no-hardlinks --no-checkout[\s\S]*--depth=1 --no-tags --single-branch[\s\S]*checkout --detach --force[\s\S]*remote remove origin[\s\S]*update-ref -d[\s\S]*--is-shallow-repository[\s\S]*rev-list --count HEAD[\s\S]*exact-head-worktree-authority\.mjs[\s\S]*BOOTSTRAP_SOURCE_PROJECTION/,
  );
  assert.match(
    localGate.match(/assert_pinned_generic_ci_node_authority\(\)[\s\S]*?\n}/)?.[0] || "",
    /3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327[\s\S]*getent passwd[\s\S]*8e5f6f3429f8cdbe693cdc29904e9d5a7b127a494bd15c804bd54c7403bfcbe7[\s\S]*generic-ci-npm-runtime-authority\.mjs[\s\S]*\/usr\/bin\/env -i/,
  );
  assert.equal(
    createHash("sha256").update(releaseRuntimeCore).digest("hex"),
    "d80450f4b05fe97569043dc605620ab2751535cb9f8e103dca4b73da2c9581c3",
  );
  assert.match(genericNpmAuthority, /assertPinnedNpmRuntime/);
  assert.equal(
    createHash("sha256").update(genericNpmAuthority).digest("hex"),
    "08b183de0fcfcbcc21bdaadff42018f4c16268222ebbb078dd046868d9f739e1",
  );
  assert.match(genericNpmAuthority, /version: "10\.9\.8"/);
  assert.match(genericNpmAuthority, /entryCount: 2_464/);
  assert.match(genericNpmAuthority, /totalBytes: 10_950_194/);
  assert.match(
    genericNpmAuthority,
    /307821a332a032c54ceadefc30718b13d0c3a2b1acdd5f4f072e3de8099d5f83/,
  );
  assert.match(
    genericNpmAuthority,
    /executableLinkTarget: "\.\.\/lib\/node_modules\/npm\/bin\/npm-cli\.js"/,
  );
  assert.doesNotMatch(genericNpmAuthority, /projectNpmRuntimeTree/);
  assert.match(
    localGate.match(/assert_pinned_operator_node_authority\(\)[\s\S]*?\n}/)?.[0] || "",
    /\/opt\/homebrew\/Cellar\/node\/24\.9\.0\/bin\/node[\s\S]*64221968[\s\S]*\/usr\/bin\/env -i[\s\S]*\/usr\/bin\/shasum[\s\S]*3e7673f6552cffd3f9eaa3bcb910198a4d0786e99bb861d24eb81cc3fce563e7/,
  );
  assert.match(localGate, /run_foundry_ci\(\)/);
  assert.match(
    localGate,
    /assert_unhooked_node_authority\(\)[\s\S]*NODE_OPTIONS[\s\S]*NODE_PATH[\s\S]*LD_PRELOAD[\s\S]*LD_AUDIT[\s\S]*LD_LIBRARY_PATH[\s\S]*DYLD_INSERT_LIBRARIES[\s\S]*DYLD_LIBRARY_PATH[\s\S]*DNAI_PORTABLE_CI_AUTHORITY/,
  );
  const operatorGate = localGate.match(
    /run_operator_host_root_tests\(\)[\s\S]*?\n}/,
  )?.[0] || "";
  assert.equal(
    (operatorGate.match(/cloudflare-operator-host-authority\.test\.mjs/g) || []).length,
    3,
  );
  assert.match(
    operatorGate,
    /assert_plain_web_ci_environment "operator-host tests"[\s\S]*assert_head_materialized_launch[\s\S]*assert_pinned_operator_node_authority[\s\S]*assert_clean_release_test_workspace "operator-host tests" true[\s\S]*operator_source_head="\$LAST_EXACT_HEAD_WORKTREE_HEAD"[\s\S]*operator_tmp="\$\(\/bin\/realpath[\s\S]*dnai-operator-root/,
  );
  assert.match(
    operatorGate,
    /clone --no-local --no-hardlinks --no-checkout[\s\S]*--depth=1 --no-tags --single-branch[\s\S]*checkout --detach --force[\s\S]*remote remove origin[\s\S]*for-each-ref[\s\S]*update-ref -d[\s\S]*objects\/info\/alternates[\s\S]*--is-shallow-repository[\s\S]*rev-list --count HEAD[\s\S]*for-each-ref --format='%\(refname\)'[\s\S]*tracked-source materialization is not exact and detached/,
  );
  assert.match(
    operatorGate,
    /release-runtime-pins-core\.mjs[\s\S]*assertPinnedReleaseRuntime[\s\S]*post-bootstrap-runtime operator materialization[\s\S]*NPM_CONFIG_USERCONFIG="\$operator_private_home\/user-npmrc"[\s\S]*NPM_CONFIG_GLOBALCONFIG="\$operator_private_home\/global-npmrc"[\s\S]*--ignore-scripts --prefix "\$operator_release_root\/web" ci[\s\S]*cloudflare-operator-host-authority\.test\.mjs[\s\S]*post-bootstrap-authority operator materialization[\s\S]*web-generated[\s\S]*Full root and web Node gates[\s\S]*cd "\$operator_release_root\/web"[\s\S]*"\$OPERATOR_NODE_EXECUTABLE" --test scripts\/\*\.test\.mjs[\s\S]*post-web operator source[\s\S]*post-web operator materialization[\s\S]*operator_materialized_head/,
  );
  const bootstrapRuntimeProof = operatorGate.indexOf(
    "assertPinnedReleaseRuntime();",
  );
  const initialDependencyInstall = operatorGate.indexOf(
    '--ignore-scripts --prefix "$operator_release_root/web" ci',
    bootstrapRuntimeProof,
  );
  const initialFullAuthorityProof = operatorGate.indexOf(
    "scripts/cloudflare-operator-host-authority.test.mjs",
    initialDependencyInstall,
  );
  const privateDirectoryCreationStart = operatorGate.indexOf(
    "/bin/mkdir -m 0700",
  );
  const privateDirectoryCreationEnd = operatorGate.indexOf(
    "/usr/bin/install -m 0600",
    privateDirectoryCreationStart,
  );
  const privateDirectoryCreationBlock = operatorGate.slice(
    privateDirectoryCreationStart,
    privateDirectoryCreationEnd,
  );
  const operatorWebGlob = operatorGate.indexOf(
    '"$OPERATOR_NODE_EXECUTABLE" --test scripts/*.test.mjs',
    initialFullAuthorityProof,
  );
  assert.ok(
    bootstrapRuntimeProof > 0
      && privateDirectoryCreationStart > 0
      && privateDirectoryCreationEnd > privateDirectoryCreationStart
      && privateDirectoryCreationEnd < bootstrapRuntimeProof
      && initialDependencyInstall > bootstrapRuntimeProof
      && initialFullAuthorityProof > initialDependencyInstall
      && operatorWebGlob > initialFullAuthorityProof,
    "operator npm runtime must be proved before its clean install, and the full authority must precede the web glob",
  );
  assert.match(
    privateDirectoryCreationBlock,
    /"\$operator_private_home\/\.npm"/,
  );
  assert.equal(
    (operatorGate.match(
      /NPM_CONFIG_CACHE="\$operator_private_home\/npm-cache"/g,
    ) || []).length,
    2,
  );
  assert.equal(
    (operatorGate.match(
      /--ignore-scripts --prefix "\$operator_release_root\/web" ci/g,
    ) || []).length,
    2,
  );
  assert.doesNotMatch(
    operatorGate,
    /NPM_CONFIG_CACHE="\$operator_private_home\/\.npm"/,
  );
  assert.match(
    operatorGate,
    /assert_pinned_operator_node_authority[\s\S]*f7373e6e34939415fe048560ecf275463ea891fec5a124a38958983f3955542d[\s\S]*cloudflare-operator-host-authority\.test\.mjs[\s\S]*cd "\$operator_release_root"[\s\S]*"\$OPERATOR_NODE_EXECUTABLE" --test scripts\/\*\.test\.mjs[\s\S]*post-root operator source[\s\S]*post-root operator materialization[\s\S]*operator root tests changed the exact materialized source commit[\s\S]*assert_pinned_operator_node_authority/,
  );
  const operatorRootGlob = operatorGate.lastIndexOf(
    '"$OPERATOR_NODE_EXECUTABLE" --test scripts/*.test.mjs',
  );
  const finalRuntimeProof = operatorGate.indexOf(
    "scripts/cloudflare-operator-host-authority.test.mjs",
    operatorRootGlob,
  );
  const finalSourceProof = operatorGate.indexOf(
    '"post-root operator source"',
    finalRuntimeProof,
  );
  assert.ok(
    operatorRootGlob > 0
      && finalRuntimeProof > operatorRootGlob
      && finalSourceProof > finalRuntimeProof,
    "operator runtime authority must be reproved after root tests and before final source proof",
  );
  assert.match(
    localGate.match(/run_foundry\(\)[\s\S]*?\n}/)?.[0] || "",
    /assert_plain_web_ci_environment "foundry operator tests"/,
  );
  assert.match(
    localGate.match(/run_foundry_ci\(\)[\s\S]*?\n}/)?.[0] || "",
    /assert_plain_web_ci_environment "foundry portable CI"[\s\S]*assert_plain_foundry_ci_environment[\s\S]*assert_head_materialized_launch[\s\S]*web\/\.npmrc[\s\S]*assert_pinned_generic_ci_node_authority[\s\S]*assert_clean_release_test_workspace "foundry portable CI"[\s\S]*foundry_authority_path[\s\S]*make_trusted_generic_ci_tool_shim[\s\S]*export HOME="\$foundry_ci_home"[\s\S]*NPM_CONFIG_USERCONFIG="\$foundry_ci_home\/user-npmrc"[\s\S]*--ignore-scripts --prefix "\$ROOT_DIR\/web" ci[\s\S]*foundry npm ci changed the reviewed web package or lock bytes[\s\S]*PATH="\$foundry_authority_path"[\s\S]*assert_pinned_generic_ci_node_authority[\s\S]*portable-root-test-profile\.mjs[\s\S]*run_foundry_ci_common[\s\S]*post-test foundry portable CI[\s\S]*PATH="\$foundry_authority_path" assert_pinned_generic_ci_foundry_authority/,
  );
  assert.match(
    localGate.match(/run_foundry_ci_common\(\)[\s\S]*?\n}/)?.[0] || "",
    /\/usr\/bin\/env -i[\s\S]*GENERIC_CI_FORGE_EXECUTABLE[\s\S]*build --sizes[\s\S]*\/usr\/bin\/env -i[\s\S]*test --threads 1[\s\S]*\/bin\/bash -p/,
  );
  assert.match(
    localGate.match(/run_portable_ci_root_tests\(\)[\s\S]*?\n}/)?.[0] || "",
    /assert_plain_web_ci_environment "portable root CI"[\s\S]*assert_clean_release_test_workspace[\s\S]*"portable root CI"[\s\S]*make_trusted_generic_ci_tool_shim[\s\S]*portable-root-test-profile\.mjs[\s\S]*run-portable-root-tests\.mjs[\s\S]*post-test portable root CI[\s\S]*assert_pinned_generic_ci_foundry_authority/,
  );
  const webGate = localGate.match(/run_web_ci\(\)[\s\S]*?\n}/)?.[0] || "";
  const outerWebGuard = localGate.match(
    /assert_plain_web_ci_environment\(\)[\s\S]*?\n}/,
  )?.[0] || "";
  assert.match(outerWebGuard, /assert_unhooked_node_authority/);
  assert.match(outerWebGuard, /VITE_\*/);
  assert.match(outerWebGuard, /PHALA/);
  assert.match(outerWebGuard, /credential_suffix/);
  const cleanWorkspaceGuard = localGate.match(
    /assert_clean_release_test_workspace\(\)[\s\S]*?\n}/,
  )?.[0] || "";
  assert.match(cleanWorkspaceGuard, /\.env\.\*[\s\S]*\.release/);
  assert.match(
    cleanWorkspaceGuard,
    /rev-parse --git-path config\.worktree[\s\S]*config_scopes=\(--local\)[\s\S]*config_scopes\+=\(--worktree\)[\s\S]*--no-includes[\s\S]*--name-only --null --list[\s\S]*config_name_lower[\s\S]*include\.\*[\s\S]*core\.fsmonitor[\s\S]*core\.attributesfile[\s\S]*filter\.\*[\s\S]*uploadpack\.packobjectshook[\s\S]*extraheader[\s\S]*credential\.\*[\s\S]*insteadof/,
  );
  assert.match(
    cleanWorkspaceGuard,
    /remote_config[\s\S]*--get-regexp[\s\S]*\[Rr\]\[Ee\]\[Mm\]\[Oo\]\[Tt\]\[Ee\][\s\S]*credential-bearing local Git remotes/,
  );
  assert.match(
    cleanWorkspaceGuard,
    /assert_exact_head_worktree_authority[\s\S]*GIT_NO_REPLACE_OBJECTS=1[\s\S]*ls-files -v -z[\s\S]*index_entry:0:1[\s\S]*symbolic-ref -q HEAD/,
  );
  assert.doesNotMatch(
    cleanWorkspaceGuard.replace(/^\s*#.*$/gm, ""),
    /status --porcelain|check-attr|\/usr\/bin\/git[^\n]*\bdiff\b/,
  );
  assert.match(
    webGate,
    /assert_plain_web_ci_environment[\s\S]*assert_head_materialized_launch[\s\S]*web\/\.npmrc[\s\S]*assert_pinned_generic_ci_node_authority[\s\S]*assert_pinned_generic_ci_foundry_authority[\s\S]*assert_clean_release_test_workspace "web portable CI"[\s\S]*dnai-web-ci-home[\s\S]*make_trusted_generic_ci_tool_shim[\s\S]*package_before[\s\S]*lock_before/,
  );
  assert.equal(
    (webGate.match(/--ignore-scripts --prefix "\$ROOT_DIR\/web" ci/g) || []).length,
    5,
  );
  assert.match(
    webGate,
    /node_modules\/typescript\/bin\/tsc --noEmit[\s\S]*node_modules\/vitest\/vitest\.mjs run[\s\S]*post-vitest web portable CI[\s\S]*run_web_npm[\s\S]*scripts\/test-harness\/run-portable-web-tests\.mjs[\s\S]*post-release-tests web portable CI[\s\S]*run_web_npm[\s\S]*node_modules\/vite\/bin\/vite\.js build[\s\S]*scripts\/build-security-headers\.mjs[\s\S]*post-build web portable CI/,
  );
  assert.match(
    webGate,
    /post-build-typecheck web portable CI[\s\S]*run_web_npm[\s\S]*node_modules\/vite\/bin\/vite\.js build[\s\S]*assert_web_control_bytes[\s\S]*post-vite web portable CI[\s\S]*assert_pinned_generic_ci_node_authority[\s\S]*run_web_npm[\s\S]*scripts\/build-security-headers\.mjs/,
  );
  assert.match(
    webGate,
    /audit-cache[\s\S]*run_web_npm "\$audit_cache" ping[\s\S]*registry\.npmjs\.org[\s\S]*run_web_npm "\$audit_cache" audit[\s\S]*audit-level=moderate[\s\S]*post-audit web portable CI[\s\S]*run_portable_ci_root_tests "\$node_executable" web-generated[\s\S]*operator-authority-fail-closed-probe\.mjs/,
  );
  assert.doesNotMatch(webGate, /run check:ci|npm run|audit:dependencies/);
  assert.equal((webGate.match(/\/usr\/bin\/env -i/g) || []).length, 3);
  assert.equal(
    (webGate.match(/NPM_CONFIG_USERCONFIG="\$web_ci_home\/user-npmrc"/g) || []).length,
    1,
  );
  assert.equal(
    (webGate.match(/NPM_CONFIG_GLOBALCONFIG="\$web_ci_home\/global-npmrc"/g) || []).length,
    1,
  );
  assert.equal((webGate.match(/NPM_CONFIG_SCRIPT_SHELL=\/bin\/sh/g) || []).length, 1);
  assert.equal((webGate.match(/NPM_CONFIG_NODE_OPTIONS=/g) || []).length, 1);
  assert.equal((webGate.match(/TMPDIR="\$web_ci_home\/tmp"/g) || []).length, 3);
  assert.equal((webGate.match(/CI=true/g) || []).length, 3);
  assert.equal(
    (webGate.match(/assert_pinned_generic_ci_node_authority/g) || []).length,
    8,
  );
  assert.match(
    webGate,
    /post-audit web portable CI[\s\S]*assert_pinned_generic_ci_node_authority[\s\S]*run_portable_ci_root_tests[\s\S]*portable root tests changed the reviewed web package, lock, or npm config[\s\S]*post-test web portable CI[\s\S]*assert_pinned_generic_ci_node_authority/,
  );
  assert.match(webGate, /trap '\/bin\/rm -rf -- "\$web_ci_home"' EXIT/);
  assert.match(localGate, /\n  web-ci\)\n    run_web_ci\n/);
  assert.match(localGate, /Usage:[^\n]*web-ci/);
  assert.match(
    localGate,
    /\n  all\)\n    run_secret_scan\n    run_operator_host_root_tests\n    run_foundry\n    run_python\n    ;;/,
  );
  assert.match(localGate, /\n  operator-host\)\n    run_operator_host_root_tests\n/);
  assert.match(localGate, /run_foundry\(\)[\s\S]*royalty-release-history-receipt\.test\.mjs/);
  assert.doesNotMatch(
    localGate.match(/run_foundry_ci\(\)[\s\S]*?\n}/)?.[0] || "",
    /royalty-release-history-receipt\.test\.mjs|royalty-release-phase-plan\.test\.mjs/,
  );
});
